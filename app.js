import express from "express";
import cors from "cors";
import mysql from "mysql";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import { format, startOfMonth, endOfMonth, parse } from "date-fns";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import moment from "moment-timezone";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
import mysql2 from "mysql2";
import { pickerTableName } from "./constants.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 3005;

const db = mysql2.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

db.getConnection((err, connection) => {
  if (err) {
    console.error("Database connection failed:", err);
  } else {
    console.log("Connected to the database");
    connection.release();
  }
});

app.use(cors());
app.use(bodyParser.json({ limit: "1mb" }));

// Middleware to verify JWT for all authenticated routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err)
      return res.status(403).json({ message: "Failed to authenticate token" });

    req.user = user;
    next();
  });
};

const convertDateToSQL = (dateString) => {
  try {
    // Parse 'dd/MM/yyyy' string to a date object
    const parsedDate = parse(dateString, "dd/MM/yyyy", new Date());

    // Check if the date is valid
    if (isNaN(parsedDate)) {
      throw new Error("Invalid date format");
    }

    // Format the parsed date to 'yyyy-MM-dd'
    return format(parsedDate, "yyyy-MM-dd");
  } catch (error) {
    console.error("Error in convertDateToSQL:", error.message);
    throw new Error("Invalid date provided");
  }
};

const covertDateFormate = (dateInput) => {
  // Ensure that the input is a valid date object
  const date = new Date(dateInput);

  // Format the date to 'dd-MM-yyyy'
  const formattedDate = format(date, "dd-MM-yyyy");
  return formattedDate;
};

/* const createAdmin = async () => {
  try {
    // Encrypt the password and tpassword
    const hashedPassword = await bcrypt.hash("1234" + process.env.SALT_KEY, 10);
    const hashedTPassword = await bcrypt.hash("1234" + process.env.SALT_KEY, 10);

    const insertQuery = `
      INSERT INTO admin (USERNAME, PASSWORD, TPASSWORD, NAME)
      VALUES (?, ?, ?, ?)
    `;

    db.query(
      insertQuery,
      ["kavi", hashedPassword, hashedTPassword, "Kaviyarasan J"],
      (err, result) => {
        if (err) {
          console.error("Error inserting into admin table:", err);
          return res
            .status(500)
            .json({ error: "Failed to insert into admin table" });
        }

        console.log("Admin record inserted successfully");
      }
    );
  } catch (error) {
    console.error("Error hashing passwords:", error);
    res.status(500).json({ error: "Failed to hash passwords" });
  }
}; */

// Add rate limiting (e.g., 100 requests per 15 minutes per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.post(
  "/login",
  [
    body("USERNAME").isString().trim().notEmpty(),
    body("PASSWORD").isString().notEmpty(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { USERNAME, PASSWORD } = req.body;

    if (!USERNAME || !PASSWORD) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required",
      });
    }

    const queryAdmin = "SELECT * FROM admin WHERE USERNAME = ?";
    const queryUser = "SELECT * FROM user WHERE USERNAME = ?";

    const handleLogin = (user, tableName) => {
      bcrypt.compare(
        PASSWORD + process.env.SALT_KEY,
        user.PASSWORD,
        (bcryptErr, bcryptResult) => {
          if (bcryptErr) {
            console.error("[LOGIN] Bcrypt error:", bcryptErr);
            return res
              .status(500)
              .json({ success: false, message: "Internal server error" });
          }
          if (!bcryptResult) {
            return res
              .status(401)
              .json({ success: false, message: "Password is incorrect" });
          }
          const currentDateTime = moment()
            .tz("Asia/Kolkata")
            .format("YYYY-MM-DD HH:mm:ss");
          const updateQuery = `UPDATE ${tableName} SET STATUS = 'ACTIVATED', LAST_LOGIN = ? WHERE USERNAME = ?`;
          db.getConnection((err, connection) => {
            if (err) {
              console.error("Error getting connection:", err);
              return res.status(500).json({ error: "Internal server error" });
            }
            connection.query(
              updateQuery,
              [currentDateTime, USERNAME],
              (updateErr) => {
                connection.release();
                if (updateErr) {
                  console.error("[LOGIN] Database update error:", updateErr);
                  return res
                    .status(500)
                    .json({ success: false, message: "Internal server error" });
                }
                const jwtToken = jwt.sign(
                  { USERNAME },
                  process.env.JWT_SECRET,
                  {
                    expiresIn: "180m",
                  }
                );
                return res.status(200).json({
                  success: true,
                  message: "Login successful",
                  jwtToken,
                  userName: USERNAME,
                  position: user.POSITION,
                  name: user.NAME,
                  userId: user.ID,
                });
              }
            );
          });
        }
      );
    };
    db.getConnection((err, connection) => {
      if (err) {
        console.error("Error getting connection:", err);
        return res.status(500).json({ error: "Internal server error" });
      }
      connection.query(queryAdmin, [USERNAME], (err, adminResults) => {
        connection.release();
        if (err) {
          console.error("[LOGIN] Database query error:", err);
          return res
            .status(500)
            .json({ success: false, message: "Internal server error" });
        }
        if (adminResults.length === 1) {
          handleLogin(adminResults[0], "admin");
        } else {
          connection.query(queryUser, [USERNAME], (err, userResults) => {
            connection.release();
            if (err) {
              console.error("[LOGIN] Database query error:", err);
              return res
                .status(500)
                .json({ success: false, message: "Internal server error" });
            }
            if (userResults.length === 1) {
              handleLogin(userResults[0], "user");
            } else {
              return res
                .status(401)
                .json({ success: false, message: "Username is incorrect" });
            }
          });
        }
      });
    });
  }
);

app.post("/logout", (req, res) => {
  const { USERID, USERNAME, POSITION } = req.body;

  const table = POSITION === "ADMIN" ? "admin" : "user";

  const updateQuery = `
          UPDATE ${table} 
          SET STATUS = ? 
          WHERE USERNAME = ? AND ID = ?
        `;

  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ message: "Error in Logout" });
    }
    connection.query(
      updateQuery,
      ["DEACTIVATED", USERNAME, USERID],
      (err, result) => {
        connection.release();
        if (err) {
          return res.status(500).json({ message: "Error in Logout" });
        }

        res.status(200).json({ message: "Logged Out" });
      }
    );
  });
});

/* Get data queries code */

/* Get jobID */
app.get("/jobID", authenticateToken, (req, res) => {
  const startDate = startOfMonth(new Date());
  const endDate = endOfMonth(new Date());

  const formattedStartDate = format(startDate, "yyyy-MM-dd");
  const formattedEndDate = format(endDate, "yyyy-MM-dd");

  const query = `
    SELECT JOB_ID 
    FROM job_details 
    WHERE IN_DATE BETWEEN ? AND ?
    ORDER BY ID DESC 
    LIMIT 1
  `;

  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ error: "Failed to execute query" });
    }
    connection.query(
      query,
      [formattedStartDate, formattedEndDate],
      (err, results) => {
        connection.release();
        if (err) {
          console.error("Error executing query:", err);
          return res.status(500).json({ error: "Failed to execute query" });
        }

        // Check if results exist and respond accordingly
        if (results.length > 0) {
          res.json({ JOB_ID: results[0].JOB_ID });
        } else {
          res.json({});
        }
      }
    );
  });
});

/* Get engineerPicker, mocPicker, assetsPicker, productPicker, faultPicker, jobStatusPicker */
app.get("/jobSheetPickers", authenticateToken, (req, res) => {
  // Queries to fetch data from each table
  const queries = {
    engineers: "SELECT NAME FROM engineers",
    moc: "SELECT NAME FROM moc",
    assets_type: "SELECT NAME FROM assets_type",
    products: "SELECT NAME FROM products",
    faults: "SELECT NAME FROM faults",
    job_status: "SELECT NAME FROM job_status",
  };

  // Execute all queries concurrently using Promise.all
  const queryPromises = Object.entries(queries).map(([key, query]) => {
    return new Promise((resolve, reject) => {
      db.getConnection((err, connection) => {
        if (err) {
          reject({ key, error: err });
        } else {
          connection.query(query, (err, results) => {
            connection.release();
            if (err) {
              reject({ key, error: err });
            } else {
              resolve({ key, data: results.map((row) => row.NAME) }); // Map results to array of names
            }
          });
        }
      });
    });
  });

  Promise.all(queryPromises)
    .then((results) => {
      // Combine results into the desired format
      const responseData = results.reduce((acc, result) => {
        acc[result.key] = result.data;
        return acc;
      }, {});

      res.json(responseData);
    })
    .catch((err) => {
      console.error("Error fetching data:", err);
      res.status(500).json({ error: "Failed to fetch data" });
    });
});

/* Get printData */
app.get("/printData", authenticateToken, (req, res) => {
  const { jobID } = req.query;

  if (!jobID) {
    return res.status(400).json({ error: "jobID is required" });
  }

  const query = "SELECT * FROM job_details WHERE JOB_ID = ?";

  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ error: "Failed to execute query" });
    }
    connection.query(query, [jobID], (err, results) => {
      connection.release();
      if (err) {
        console.error("Error executing query:", err);
        return res.status(500).json({ error: "Failed to execute query" });
      }

      if (results.length === 0) {
        return res.json([]);
      }

      const formattedResults = results.map((result) => ({
        ...result,
        IN_DATE: covertDateFormate(result.IN_DATE),
        OUT_DATE: covertDateFormate(result.OUT_DATE),
      }));

      res.json(formattedResults);
    });
  });
});

/* Get allData */
app.get("/allData", authenticateToken, (req, res) => {
  const { inDateFrom, inDateTo, status } = req.query;

  if (!inDateFrom || !inDateTo || !status) {
    return res
      .status(400)
      .json({ error: "inDateFrom, inDateTo, and status are required" });
  }

  // Convert inDateFrom and inDateTo from dd/MM/yyyy to yyyy-MM-dd
  const convertedInDateFrom = convertDateToSQL(inDateFrom); // Convert to 'yyyy-MM-dd'
  const convertedInDateTo = convertDateToSQL(inDateTo); // Convert to 'yyyy-MM-dd'

  // Adjust the query based on the status value
  let query = `
    SELECT * 
    FROM job_details 
    WHERE IN_DATE BETWEEN ? AND ?
  `;

  const queryParams = [convertedInDateFrom, convertedInDateTo];

  // If status is not "all", add the condition for JOB_STATUS
  if (status !== "All" && status !== "Un Purchased" && status !== "Purchased") {
    query += ` AND JOB_STATUS = ?`;
    queryParams.push(status);
  }

  if (status === "Un Purchased") {
    query += ` AND PURCHASED = 'NO'`;
    queryParams.push(status);
  }

  if (status === "Purchased") {
    query += ` AND PURCHASED = 'YES'`;
    queryParams.push(status);
  }

  query += ` ORDER BY ID DESC`;

  // Execute the query
  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    connection.query(query, queryParams, (err, results) => {
      connection.release();
      if (err) {
        console.error("Database query error:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      // Modify the results
      const modifiedResults = results.map((row, index) => {
        const { ID, IN_DATE, OUT_DATE, ...rest } = row;

        return {
          newID: index + 1, // Generate a new ID
          IN_DATE: covertDateFormate(IN_DATE), // Format to 'dd-MM-yyyy'
          OUT_DATE: covertDateFormate(OUT_DATE), // Format to 'dd-MM-yyyy'
          ...rest, // Other data
        };
      });

      res.status(200).json(modifiedResults); // Send the modified results
    });
  });
});

/* Get userList */
app.get("/userList", authenticateToken, (req, res) => {
  // Select all users from the user table
  const query = "SELECT * FROM user";

  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    connection.query(query, (err, results) => {
      connection.release();
      if (err) {
        console.error("Database query error:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      // Send the results directly
      res.status(200).json(results);
    });
  });
});

/* Get modify Pickers */
app.get("/pickersList", authenticateToken, (req, res) => {
  const { menuSelected } = req.query;

  // Validate menuSelected
  if (!pickerTableName[menuSelected]) {
    return res.status(400).json({ error: "Invalid menuSelected value" });
  }

  // Construct the query
  const query = `SELECT NAME FROM ${pickerTableName[menuSelected]}`;

  // Execute the query
  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    connection.query(query, (err, results) => {
      connection.release();
      if (err) {
        console.error("Database query error:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      // If no results found
      if (results.length === 0) {
        return res.status(404).json({ message: "No data found" });
      }

      // Send the results as an array of names
      const names = results.map((row) => row.NAME);
      res.status(200).json(names);
    });
  });
});

/* Get insight */
app.post("/reports", authenticateToken, (req, res) => {
  const { inDateFrom, inDateTo, filter, admintPassword, userName, userId } =
    req.body;

  // Basic validation
  if (
    !inDateFrom ||
    !inDateTo ||
    !filter ||
    !admintPassword ||
    !userName ||
    !userId
  ) {
    return res.status(400).json({
      error:
        "inDateFrom, inDateTo, filter, admintPassword, userName, and userId are required",
    });
  }

  // Step 1: Verify admin's transaction password
  const selectQuery =
    "SELECT TPASSWORD FROM admin WHERE USERNAME = ? AND ID = ?";
  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ error: "Database error" });
    }

    connection.query(selectQuery, [userName, userId], (err, results) => {
      connection.release();
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (!results || results.length === 0) {
        return res.status(404).json({ error: "Admin not found" });
      }

      const storedPassword = results[0].TPASSWORD;

      bcrypt.compare(
        admintPassword + process.env.SALT_KEY,
        storedPassword,
        (bcryptErr, isMatch) => {
          if (bcryptErr) {
            console.error("Bcrypt error:", bcryptErr);
            return res.status(500).json({ error: "Internal server error" });
          }

          if (!isMatch) {
            return res
              .status(400)
              .json({ error: "Transaction password is incorrect" });
          }

          // Step 2: Continue with report generation
          const convertedInDateFrom = convertDateToSQL(inDateFrom);
          const convertedInDateTo = convertDateToSQL(inDateTo);
          const queryParams = [convertedInDateFrom, convertedInDateTo];

          let query = "";
          switch (filter) {
            case "MOC":
              query = `
              SELECT MOC as MODE, COUNT(MOC) as COUNT
              FROM job_details 
              WHERE IN_DATE BETWEEN ? AND ?
              GROUP BY MOC
            `;
              break;

            case "Profit":
              query = `
              SELECT JOB_ID, AMOUNT, PURCHASE_AMOUNT, IN_DATE, OUT_DATE
              FROM job_details 
              WHERE IN_DATE BETWEEN ? AND ?
            `;
              break;

            default:
              return res.status(400).json({ error: "Invalid filter value" });
          }

          db.getConnection((err, connection) => {
            if (err) {
              console.error("Error getting connection:", err);
              return res.status(500).json({ error: "Internal Server Error" });
            }

            connection.query(query, queryParams, (err, results) => {
              connection.release();

              if (err) {
                console.error("Database query error:", err);
                return res.status(500).json({ error: "Internal Server Error" });
              }

              // If filter is Profit, format the dates
              if (filter === "Profit") {
                const modifiedResults = results.map((row) => {
                  const { IN_DATE, OUT_DATE, ...rest } = row;
                  return {
                    IN_DATE: covertDateFormate(IN_DATE), // Format to 'dd-MM-yyyy'
                    OUT_DATE: covertDateFormate(OUT_DATE), // Format to 'dd-MM-yyyy'
                    ...rest,
                  };
                });
                return res.status(200).json(modifiedResults);
              }

              // Otherwise, return as is (e.g., for MOC)
              res.status(200).json(results);
            });
          });
        }
      );
    });
  });
});

/* Get Customer Details */
app.get("/searchCustomer", authenticateToken, (req, res) => {
  const { mobile, name } = req.query;

  if (!mobile && !name) {
    return res
      .status(400)
      .json({ error: "Please provide mobile or name for search" });
  }

  let query =
    "SELECT NAME, MOBILE, EMAIL, ADDRESS FROM customer_details WHERE ";
  const conditions = [];
  const params = [];

  if (mobile) {
    conditions.push("MOBILE LIKE ?");
    params.push(`%${mobile}%`);
  }

  if (name) {
    conditions.push("NAME LIKE ?");
    params.push(`%${name}%`);
  }

  query += conditions.join(" OR "); // Match any one

  db.query(query, params, (err, results) => {
    if (err) {
      console.error("Error fetching customer data:", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    res.json({ customers: results });
  });
});

/* Get customer details */
app.get("/customerDetails", authenticateToken, (req, res) => {
  const query = "SELECT ID, NAME, MOBILE, EMAIL, ADDRESS FROM customer_details";

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching customer details:", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    res.json({ customers: results });
  });
});

/* end of Get data queries code */

/* Insert data into job_details and backup */
app.post("/insert", authenticateToken, (req, res) => {
  const {
    jobID,
    customerName,
    mobileNo,
    email,
    address,
    engineer,
    moc,
    assets,
    productMake,
    description,
    serialNo,
    faultType,
    faultDesc,
    jobStatus,
    amount,
    solutionProvided,
    inDate,
    outDate,
    name,
  } = req.body;

  const convertedInDate = convertDateToSQL(inDate);
  const convertedOutDate = convertDateToSQL(outDate);

  const checkJobIDQuery = "SELECT 1 FROM job_details WHERE JOB_ID = ? LIMIT 1";
  const checkCustomerQuery =
    "SELECT 1 FROM customer_details WHERE NAME = ? AND MOBILE = ? LIMIT 1";
  const insertCustomerQuery =
    "INSERT INTO customer_details (NAME, MOBILE, EMAIL, ADDRESS) VALUES (?, ?, ?, ?)";

  const insertJobQuery = `
    INSERT INTO job_details 
    (JOB_ID, NAME, MOBILE, EMAIL, ADDRESS, ENGINEER, MOC, IN_DATE, OUT_DATE, 
     ASSETS, PRODUCT_MAKE, DESCRIPTION, SERIAL_NO, FAULT_TYPE, FAULT_DESC, 
     JOB_STATUS, AMOUNT, SOLUTION_PROVIDED, CREATED, LAST_MODIFIED) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const jobData = [
    jobID,
    customerName,
    mobileNo,
    email,
    address,
    engineer,
    moc,
    convertedInDate,
    convertedOutDate,
    assets,
    productMake,
    description,
    serialNo,
    faultType,
    faultDesc,
    jobStatus,
    amount,
    solutionProvided,
    name,
    name,
  ];

  db.getConnection((err, connection) => {
    if (err) return res.status(500).json({ error: "Connection failed" });

    // Step 1: Check job ID
    connection.query(checkJobIDQuery, [jobID], (err, results) => {
      if (err) {
        connection.release();
        return res.status(500).json({ error: "Job ID check failed" });
      }

      if (results.length > 0) {
        connection.release();
        return res.status(400).json({ error: "Job ID already exists" });
      }

      // Step 2: Check if customer exists
      connection.query(
        checkCustomerQuery,
        [customerName, mobileNo, email, address],
        (err, results) => {
          if (err) {
            connection.release();
            return res.status(500).json({ error: "Customer check failed" });
          }

          const proceedWithJobInsert = () => {
            connection.query(insertJobQuery, jobData, (err) => {
              connection.release();
              if (err)
                return res.status(500).json({ error: "Job insert failed" });
              res.json({ message: "Job inserted successfully" });
            });
          };

          // Step 3: Insert customer if not found
          if (results.length === 0) {
            connection.query(
              insertCustomerQuery,
              [customerName, mobileNo, email, address],
              (err) => {
                if (err) {
                  connection.release();
                  return res
                    .status(500)
                    .json({ error: "Customer insert failed" });
                }
                proceedWithJobInsert();
              }
            );
          } else {
            proceedWithJobInsert();
          }
        }
      );
    });
  });
});

/* insert picker */
app.post("/insertPicker", authenticateToken, (req, res) => {
  const { menuSelected, pickerName } = req.body;
  const checkPickerQuery = `SELECT 1 FROM ${pickerTableName[menuSelected]} WHERE NAME = ? LIMIT 1`;
  const insertQuery = `INSERT INTO ${pickerTableName[menuSelected]} (NAME) VALUES (?)`;

  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ error: "Transaction failed to start" });
    }

    connection.query(checkPickerQuery, [pickerName], (err, results) => {
      connection.release();
      if (err) {
        return res.status(500).json({ error: "Error checking picker name" });
      }

      if (results.length > 0) {
        return res.status(400).json({ error: "Picker name already exists" });
      }

      // Insert new picker name
      connection.query(insertQuery, [pickerName], (err) => {
        if (err) {
          return res.status(500).json({ error: "Error inserting picker name" });
        }

        res.json({ message: "Picker details inserted successfully" });
      });
    });
  });
});

app.post("/createUser", authenticateToken, (req, res) => {
  const {
    newUserName,
    newName,
    newPassword,
    admintPassword,
    position,
    userName,
    userId,
  } = req.body;

  if (position !== "ADMIN") {
    return res.status(400).json({ message: "Unauthorized access" });
  }

  // Step 1: Verify admin's transaction password
  const selectQuery =
    "SELECT TPASSWORD FROM admin WHERE USERNAME = ? AND ID = ?";
  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ message: "Database error" });
    }
    connection.query(selectQuery, [userName, userId], (err, results) => {
      connection.release();
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: "Database error" });
      }

      // Check if admin record was found
      if (!results || results.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const storedPassword = results[0].TPASSWORD;

      // Compare the old password with the stored one
      bcrypt.compare(
        admintPassword + process.env.SALT_KEY,
        storedPassword,
        (bcryptErr, isMatch) => {
          if (bcryptErr) {
            console.error("Bcrypt error:", bcryptErr);
            return res.status(500).json({ message: "Internal server error" });
          }

          if (!isMatch) {
            return res
              .status(400)
              .json({ message: "Transaction password is incorrect" });
          }

          // Step 2: Check if the new username already exists
          const checkUsernameQuery = "SELECT 1 FROM user WHERE USERNAME = ?";
          db.getConnection((err, connection) => {
            if (err) {
              console.error("Error getting connection:", err);
              return res.status(500).json({ message: "Database error" });
            }
            connection.query(
              checkUsernameQuery,
              [newUserName],
              (err, userResult) => {
                connection.release();
                if (err) {
                  console.error("Database error:", err);
                  return res.status(500).json({ message: "Database error" });
                }

                if (userResult && userResult.length > 0) {
                  return res
                    .status(400)
                    .json({ message: "Username already exists" });
                }

                // Step 3: Hash the new password
                bcrypt.hash(
                  newPassword + process.env.SALT_KEY,
                  10,
                  (hashErr, hashedPassword) => {
                    if (hashErr) {
                      console.error("Error hashing password:", hashErr);
                      return res
                        .status(500)
                        .json({ message: "Internal server error" });
                    }

                    // Step 4: Proceed with user creation
                    const insertQuery =
                      "INSERT INTO user (USERNAME, NAME, PASSWORD) VALUES (?, ?, ?)";
                    db.getConnection((err, connection) => {
                      if (err) {
                        console.error("Error getting connection:", err);
                        return res
                          .status(500)
                          .json({ message: "Database error" });
                      }
                      connection.query(
                        insertQuery,
                        [newUserName, newName, hashedPassword],
                        (err) => {
                          connection.release();
                          if (err) {
                            console.error("Error creating user:", err);
                            return res
                              .status(500)
                              .json({ message: "Error Creating User" });
                          }

                          res
                            .status(200)
                            .json({ message: "User Created successfully" });
                        }
                      );
                    });
                  }
                );
              }
            );
          });
        }
      );
    });
  });
});

/* update query */
app.post("/editJob", authenticateToken, (req, res) => {
  const {
    oldJobID,
    jobID,
    customerName,
    mobileNo,
    email,
    address,
    engineer,
    moc,
    inDate,
    outDate,
    assets,
    productMake,
    serialNo,
    description,
    faultType,
    faultDesc,
    jobStatus,
    solutionProvided,
    amount,
    purchaseAmount,
    purchasedStatus,
    name,
  } = req.body;

  const convertedInDate = convertDateToSQL(inDate);
  const convertedOutDate = convertDateToSQL(outDate);

  const checkJobIDQuery = "SELECT 1 FROM job_details WHERE JOB_ID = ? LIMIT 1";
  const checkCustomerQuery =
    "SELECT 1 FROM customer_details WHERE NAME = ? AND MOBILE = ? LIMIT 1";
  const insertCustomerQuery =
    "INSERT INTO customer_details (NAME, MOBILE) VALUES (?, ?)";

  const updateQuery = `
    UPDATE job_details 
    SET JOB_ID = ?, NAME = ?, MOBILE = ?, EMAIL = ?, ADDRESS = ?, ENGINEER = ?, MOC = ?, 
        IN_DATE = ?, OUT_DATE = ?, ASSETS = ?, PRODUCT_MAKE = ?, DESCRIPTION = ?, 
        SERIAL_NO = ?, FAULT_TYPE = ?, FAULT_DESC = ?, JOB_STATUS = ?, AMOUNT = ?, 
        SOLUTION_PROVIDED = ?, PURCHASE_AMOUNT=?, PURCHASED=?, LAST_MODIFIED=? 
    WHERE JOB_ID = ?
  `;

  const updateData = [
    jobID,
    customerName,
    mobileNo,
    email,
    address,
    engineer,
    moc,
    convertedInDate,
    convertedOutDate,
    assets,
    productMake,
    description,
    serialNo,
    faultType,
    faultDesc,
    jobStatus,
    amount,
    solutionProvided,
    purchaseAmount,
    purchasedStatus,
    name,
    oldJobID,
  ];

  db.getConnection((err, connection) => {
    if (err)
      return res
        .status(500)
        .json({ success: false, message: "Connection failed" });

    const updateJob = () => {
      connection.query(updateQuery, updateData, (err) => {
        connection.release();
        if (err)
          return res
            .status(500)
            .json({ success: false, message: "Job update failed" });
        res
          .status(200)
          .json({ success: true, message: "Job updated successfully" });
      });
    };

    const handleCustomerCheck = () => {
      connection.query(
        checkCustomerQuery,
        [customerName, mobileNo],
        (err, results) => {
          if (err) {
            connection.release();
            return res
              .status(500)
              .json({ success: false, message: "Customer check failed" });
          }

          if (results.length === 0) {
            connection.query(
              insertCustomerQuery,
              [customerName, mobileNo],
              (err) => {
                if (err) {
                  connection.release();
                  return res.status(500).json({
                    success: false,
                    message: "Customer insert failed",
                  });
                }
                updateJob();
              }
            );
          } else {
            updateJob();
          }
        }
      );
    };

    if (jobID !== oldJobID) {
      connection.query(checkJobIDQuery, [jobID], (err, results) => {
        if (err) {
          connection.release();
          return res
            .status(500)
            .json({ success: false, message: "Job ID check failed" });
        }

        if (results.length > 0) {
          connection.release();
          return res
            .status(400)
            .json({ success: false, message: "Job ID already exists" });
        }

        handleCustomerCheck();
      });
    } else {
      handleCustomerCheck();
    }
  });
});

app.post("/editJobStatus", authenticateToken, (req, res) => {
  const { jobID, jobStatus } = req.body;

  if (!jobID || !jobStatus) {
    return res
      .status(400)
      .json({ success: false, message: "Missing jobID or jobStatus" });
  }

  const updateQuery = `UPDATE job_details SET JOB_STATUS = ? WHERE JOB_ID = ?`;

  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting DB connection:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database connection failed" });
    }

    connection.query(updateQuery, [jobStatus, jobID], (err, results) => {
      connection.release();

      if (err) {
        console.error("Error executing query:", err);
        return res
          .status(500)
          .json({ success: false, message: "Failed to update job status" });
      }

      if (results.affectedRows === 0) {
        return res
          .status(404)
          .json({ success: false, message: "Job ID not found" });
      }

      return res
        .status(200)
        .json({ success: true, message: "Job status updated successfully" });
    });
  });
});

app.post("/changePassword", authenticateToken, (req, res) => {
  const { oldPassword, newPassword, userName, userId, position } = req.body;

  // Determine the table to use based on position
  const table = position === "ADMIN" ? "admin" : "user";

  const selectQuery = `
    SELECT PASSWORD 
    FROM ${table} 
    WHERE USERNAME = ? AND ID = ?
  `;

  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    connection.query(selectQuery, [userName, userId], (err, result) => {
      connection.release();
      if (err) {
        return res.status(500).json({ message: "Database error", error: err });
      }

      if (result.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const storedPassword = result[0].PASSWORD;

      // Compare the old password with the stored one
      bcrypt.compare(
        oldPassword + process.env.SALT_KEY,
        storedPassword,
        (err, isMatch) => {
          if (err) {
            return res
              .status(500)
              .json({ message: "Error comparing passwords" });
          }

          if (!isMatch) {
            return res
              .status(400)
              .json({ message: "Old password is incorrect" });
          }

          // Hash the new password with the salt and bcrypt
          bcrypt.hash(
            newPassword + process.env.SALT_KEY,
            10,
            (err, hashedPassword) => {
              if (err) {
                return res
                  .status(500)
                  .json({ message: "Error hashing new password" });
              }

              const updateQuery = `
          UPDATE ${table} 
          SET PASSWORD = ? 
          WHERE USERNAME = ? AND ID = ?
        `;

              db.getConnection((err, connection) => {
                if (err) {
                  console.error("Error getting connection:", err);
                  return res
                    .status(500)
                    .json({ message: "Error updating password" });
                }
                connection.query(
                  updateQuery,
                  [hashedPassword, userName, userId],
                  (err, result) => {
                    connection.release();
                    if (err) {
                      return res
                        .status(500)
                        .json({ message: "Error updating password" });
                    }

                    res
                      .status(200)
                      .json({ message: "Password updated successfully" });
                  }
                );
              });
            }
          );
        }
      );
    });
  });
});

app.post("/changeTPassword", authenticateToken, (req, res) => {
  const { oldPassword, newPassword, userName, userId, position } = req.body;

  if (position !== "ADMIN") {
    return res.status(400).json({ message: "Unauthorized access" });
  }

  const selectQuery = `
    SELECT TPASSWORD 
    FROM admin 
    WHERE USERNAME = ? AND ID = ?
  `;

  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ message: "Database error", error: err });
    }
    connection.query(selectQuery, [userName, userId], (err, result) => {
      connection.release();
      if (err) {
        return res.status(500).json({ message: "Database error", error: err });
      }

      if (result.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const storedPassword = result[0].TPASSWORD;

      // Compare the old password with the stored one
      bcrypt.compare(
        oldPassword + process.env.SALT_KEY,
        storedPassword,
        (err, isMatch) => {
          if (err) {
            return res
              .status(500)
              .json({ message: "Error comparing passwords" });
          }

          if (!isMatch) {
            return res
              .status(400)
              .json({ message: "Old password is incorrect" });
          }

          // Hash the new password with the salt and bcrypt
          bcrypt.hash(
            newPassword + process.env.SALT_KEY,
            10,
            (err, hashedPassword) => {
              if (err) {
                return res
                  .status(500)
                  .json({ message: "Error hashing new password" });
              }

              const updateQuery = `
          UPDATE admin 
          SET TPASSWORD = ? 
          WHERE USERNAME = ? AND ID = ?
        `;

              db.getConnection((err, connection) => {
                if (err) {
                  console.error("Error getting connection:", err);
                  return res
                    .status(500)
                    .json({ message: "Error updating password" });
                }
                connection.query(
                  updateQuery,
                  [hashedPassword, userName, userId],
                  (err, result) => {
                    connection.release();
                    if (err) {
                      return res
                        .status(500)
                        .json({ message: "Error updating password" });
                    }

                    res
                      .status(200)
                      .json({ message: "Password updated successfully" });
                  }
                );
              });
            }
          );
        }
      );
    });
  });
});

app.post("/resetPassword", authenticateToken, async (req, res) => {
  const { userName, position } = req.body;

  if (position !== "ADMIN") {
    return res.status(400).json({ message: "Unauthorized access" });
  }

  // Check if userName is provided
  if (!userName) {
    return res.status(400).json({ message: "Username is required" });
  }

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(
      "Abc@123" + process.env.SALT_KEY,
      10
    );

    // Prepare the update query
    const updateQuery = "UPDATE user SET PASSWORD = ? WHERE USERNAME = ?";

    // Execute the update query
    db.getConnection((err, connection) => {
      if (err) {
        console.error("Error getting connection:", err);
        return res.status(500).json({ message: "Error updating password" });
      }
      connection.query(
        updateQuery,
        [hashedPassword, userName],
        (err, result) => {
          connection.release();
          if (err) {
            console.error("Error updating password:", err);
            return res.status(500).json({ message: "Error updating password" });
          }

          if (result.affectedRows === 0) {
            return res.status(404).json({ message: "User not found" });
          }

          res.status(200).json({
            message: `Password reset to Abc@123 for user - ${userName}`,
          });
        }
      );
    });
  } catch (error) {
    console.error("Error hashing new password:", error);
    res.status(500).json({ message: "Error resetting password" });
  }
});

app.post("/editPicker", authenticateToken, (req, res) => {
  const { menuSelected, oldPicker, newPicker, position } = req.body;

  if (position !== "ADMIN") {
    return res.status(403).json({ message: "Unauthorized access" });
  }

  const checkPickerExistsQuery = `SELECT 1 FROM ${pickerTableName[menuSelected]} WHERE NAME = ? LIMIT 1`;
  const updateQuery = `
    UPDATE ${pickerTableName[menuSelected]} 
    SET NAME = ? 
    WHERE NAME = ?
  `;

  db.getConnection((err, connection) => {
    if (err) {
      console.error("Error getting connection:", err);
      return res.status(500).json({ error: "Failed to start transaction" });
    }

    // Check if the new picker name already exists in the table
    connection.query(checkPickerExistsQuery, [newPicker], (err, results) => {
      connection.release();
      if (err) {
        return res.status(500).json({ error: "Failed to check picker name" });
      }

      if (results.length > 0) {
        return res
          .status(400)
          .json({ error: "New picker name already exists" });
      }

      // Perform the update
      connection.query(updateQuery, [newPicker, oldPicker], (err, result) => {
        if (err) {
          return res
            .status(500)
            .json({ error: "Failed to update picker name" });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({ error: "Old picker name not found" });
        }

        res.json({ message: "Picker name updated successfully" });
      });
    });
  });
});

app.put("/editCustomer", authenticateToken, (req, res) => {
  const { id, name, mobile, email, address } = req.body;

  if (!id || !name || !mobile) {
    return res.status(400).json({ error: "ID, NAME, and MOBILE are required" });
  }

  const emailValue = email || "";
  const addressValue = address || "";

  const query = `
    UPDATE customer_details 
    SET NAME = ?, MOBILE = ?, EMAIL = ?, ADDRESS = ?
    WHERE ID = ?
  `;

  db.query(
    query,
    [name, mobile, emailValue, addressValue, id],
    (err, result) => {
      if (err) {
        console.error("Error updating customer:", err);
        return res.status(500).json({ error: "Internal server error" });
      }

      if (result.affectedRows === 0) {
        return res
          .status(404)
          .json({ message: "Customer not found or no changes made" });
      }

      res.json({ message: "Customer updated successfully" });
    }
  );
});

/* Delete Queries */
app.post("/deleteUser", authenticateToken, async (req, res) => {
  const { userName, position } = req.body;

  // Validate admin access
  if (position !== "ADMIN") {
    return res.status(403).json({ message: "Unauthorized access" });
  }

  // Check if userName is provided
  if (!userName) {
    return res.status(400).json({ message: "Username is required" });
  }

  try {
    // Prepare the delete query
    const deleteQuery = "DELETE FROM user WHERE USERNAME = ?";

    // Execute the delete query
    db.getConnection((err, connection) => {
      if (err) {
        console.error("Error getting connection:", err);
        return res.status(500).json({ message: "Error deleting user" });
      }
      connection.query(deleteQuery, [userName], (err, result) => {
        connection.release();
        if (err) {
          console.error("Error deleting user:", err);
          return res.status(500).json({ message: "Error deleting user" });
        }

        // Check if any rows were affected
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        res
          .status(200)
          .json({ message: `User '${userName}' deleted successfully.` });
      });
    });
  } catch (error) {
    console.error("Unexpected error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/deleteJob", authenticateToken, async (req, res) => {
  const { JobID, position } = req.body;

  // Validate admin access
  if (position !== "ADMIN") {
    return res.status(403).json({ message: "Unauthorized access" });
  }

  // Check if JobID is provided
  if (!JobID) {
    return res.status(400).json({ message: "JobID is required" });
  }

  try {
    // Prepare the delete query
    const deleteQuery = "DELETE FROM job_details WHERE JOB_ID = ?";

    // Execute the delete query
    db.getConnection((err, connection) => {
      if (err) {
        console.error("Error getting connection:", err);
        return res.status(500).json({ message: "Error deleting job" });
      }
      connection.query(deleteQuery, [JobID], (err, result) => {
        connection.release();
        if (err) {
          console.error("Error deleting job:", err);
          return res.status(500).json({ message: "Error deleting job" });
        }

        // Check if any rows were affected
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: "Job not found." });
        }

        res
          .status(200)
          .json({ message: `Job '${JobID}' deleted successfully.` });
      });
    });
  } catch (error) {
    console.error("Unexpected error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/deletePicker", authenticateToken, async (req, res) => {
  const { menuSelected, pickerName, position } = req.body;

  // Validate admin access
  if (position !== "ADMIN") {
    return res.status(403).json({ message: "Unauthorized access" });
  }

  // Check if userName is provided
  if (!menuSelected) {
    return res.status(400).json({ message: "Menu is required" });
  }

  if (!pickerName) {
    return res.status(400).json({ message: "Picker is required" });
  }

  try {
    // Prepare the delete query
    const deleteQuery = `DELETE FROM ${pickerTableName[menuSelected]} WHERE NAME = ?`;

    // Execute the delete query
    db.getConnection((err, connection) => {
      if (err) {
        console.error("Error getting connection:", err);
        return res.status(500).json({ message: "Error deleting picker" });
      }
      connection.query(deleteQuery, [pickerName], (err, result) => {
        connection.release();
        if (err) {
          console.error("Error deleting user:", err);
          return res.status(500).json({ message: "Error deleting picker" });
        }

        // Check if any rows were affected
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: "picker not found" });
        }

        res
          .status(200)
          .json({ message: `Picker '${pickerName}' deleted successfully.` });
      });
    });
  } catch (error) {
    console.error("Unexpected error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.delete("/deleteCustomer", authenticateToken, (req, res) => {
  const { name, mobile } = req.body;

  if (!name || !mobile) {
    return res.status(400).json({ error: "Name and mobile are required" });
  }

  const query = "DELETE FROM customer_details WHERE NAME = ? AND MOBILE = ?";
  db.query(query, [name, mobile], (err, result) => {
    if (err) {
      console.error("Error deleting customer:", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Customer not found" });
    }

    res.json({ message: "Customer deleted successfully" });
  });
});

// Centralized error handler
app.use((err, req, res, next) => {
  console.error("[ERROR]", err);
  res.status(500).json({ message: "Internal server error" });
});

/* Start server */
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
