import express from "express";
import cors from "cors";
import mysql from "mysql";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import { format, startOfMonth, endOfMonth, parse } from "date-fns";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import moment from "moment-timezone";

dotenv.config();

const app = express();
const port = process.env.PORT || 3005;

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
  } else {
    console.log("Connected to the database");
  }
});

app.use(cors());
app.use(bodyParser.json());

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

app.post("/login", (req, res) => {
  const { USERNAME, PASSWORD } = req.body;

  const queryAdmin = "SELECT * FROM admin WHERE USERNAME = ?";
  const queryUser = "SELECT * FROM user WHERE USERNAME = ?";

  const handleLogin = (user, tableName) => {
    bcrypt.compare(
      PASSWORD + process.env.SALT_KEY,
      user.PASSWORD,
      (bcryptErr, bcryptResult) => {
        if (bcryptErr) {
          console.error("Bcrypt error:", bcryptErr);
          return res.status(500).json({ message: "Internal server error" });
        }

        if (!bcryptResult) {
          return res.status(401).json({ message: "Password is wrong" });
        }

        const currentDateTime = moment()
          .tz("Asia/Kolkata")
          .format("YYYY-MM-DD HH:mm:ss");

        const updateQuery = `UPDATE ${tableName} SET STATUS = 'ACTIVATED', LAST_LOGIN = ? WHERE USERNAME = ?`;

        db.query(updateQuery, [currentDateTime, USERNAME], (updateErr) => {
          if (updateErr) {
            console.error("Database update error:", updateErr);
            return res.status(500).json({ message: "Internal server error" });
          }

          const jwtToken = jwt.sign({ USERNAME }, process.env.JWT_SECRET, {
            expiresIn: "90m",
          });

          return res.json({
            jwtToken,
            userName: USERNAME,
            position: user.POSITION,
            name: user.NAME,
            userId: user.ID,
          });
        });
      }
    );
  };

  // Check admin credentials
  db.query(queryAdmin, [USERNAME], (err, adminResults) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    if (adminResults.length === 1) {
      // User found in admin table
      handleLogin(adminResults[0], "admin");
    } else {
      // User not found in admin, check user table
      db.query(queryUser, [USERNAME], (err, userResults) => {
        if (err) {
          console.error("Database query error:", err);
          return res.status(500).json({ message: "Internal server error" });
        }

        if (userResults.length === 1) {
          // User found in user table
          handleLogin(userResults[0], "user");
        } else {
          return res.status(401).json({ message: "Username is wrong" });
        }
      });
    }
  });
});

app.post("/logout", (req, res) => {
  const { USERID, USERNAME, POSITION } = req.body;

  const table = POSITION === "ADMIN" ? "admin" : "user";

  const updateQuery = `
          UPDATE ${table} 
          SET STATUS = ? 
          WHERE USERNAME = ? AND ID = ?
        `;

  db.query(updateQuery, ["DEACTIVATED", USERNAME, USERID], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error in Logout" });
    }

    res.status(200).json({ message: "Logged Out" });
  });
});

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

  db.query(query, [formattedStartDate, formattedEndDate], (err, results) => {
    if (err) {
      console.error("Error executing query:", err);
      return res.status(500).json({ error: "Failed to execute query" });
    }

    res.json(results.length ? results : []); // Return result or empty array
  });
});

/* Get printData */
app.get("/printData", authenticateToken, (req, res) => {
  const { jobID } = req.query;

  if (!jobID) {
    return res.status(400).json({ error: "jobID is required" });
  }

  const query = `SELECT * FROM job_details WHERE JOB_ID = ?`;

  db.query(query, [jobID], (err, results) => {
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
  if (status !== "All") {
    query += ` AND JOB_STATUS = ?`;
    queryParams.push(status);
  }

  query += ` ORDER BY IN_DATE ASC`;

  // Execute the query
  db.query(query, queryParams, (err, results) => {
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

app.get("/userList", authenticateToken, (req, res) => {
  // Select all users from the user table
  const query = "SELECT * FROM user";

  db.query(query, (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // Send the results directly
    res.status(200).json(results);
  });
});

app.get("/insight", authenticateToken, (req, res) => {
  const { inDateFrom, inDateTo, filter } = req.query;

  if (!inDateFrom || !inDateTo || !filter) {
    return res
      .status(400)
      .json({ error: "inDateFrom, inDateTo, and filter are required" });
  }

  // Convert inDateFrom and inDateTo from dd/MM/yyyy to yyyy-MM-dd
  const convertedInDateFrom = convertDateToSQL(inDateFrom); // Convert to 'yyyy-MM-dd'
  const convertedInDateTo = convertDateToSQL(inDateTo); // Convert to 'yyyy-MM-dd'

  // Adjust the query based on the status value
  let query = `
    SELECT MOC as MODE,  COUNT(MOC) as COUNT
    FROM job_details 
    WHERE IN_DATE BETWEEN ? AND ? GROUP BY MOC
  `;

  const queryParams = [convertedInDateFrom, convertedInDateTo];

  // Execute the query
  db.query(query, queryParams, (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.status(200).json(results);
  });
});

/* Get allData */

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

  const commonData = [
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

  const checkJobIDQuery = "SELECT 1 FROM job_details WHERE JOB_ID = ? LIMIT 1";
  const insertQuery = `
    INSERT INTO job_details 
    (JOB_ID, NAME, MOBILE, EMAIL, ADDRESS, ENGINEER, MOC, IN_DATE, OUT_DATE, 
     ASSETS, PRODUCT_MAKE, DESCRIPTION, SERIAL_NO, FAULT_TYPE, FAULT_DESC, 
     JOB_STATUS, AMOUNT, SOLUTION_PROVIDED, CREATED, LAST_MODIFIED) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.beginTransaction((err) => {
    if (err) {
      console.error("Transaction Error:", err);
      return res.status(500).json({ error: "Transaction failed to start" });
    }

    // Check if jobID already exists
    db.query(checkJobIDQuery, [jobID], (err, results) => {
      if (err) {
        return db.rollback(() => {
          console.error("Job ID Check Error:", err);
          return res.status(500).json({ error: "Error checking Job ID" });
        });
      }

      if (results.length > 0) {
        return res.status(400).json({ error: "Job ID already exists" });
      }

      // Proceed with insert if jobID does not exist
      db.query(insertQuery, commonData, (err) => {
        if (err) {
          return db.rollback(() => {
            console.error("Insert Error:", err);
            return res.status(500).json({ error: "Error inserting record" });
          });
        }

        db.commit((err) => {
          if (err) {
            return db.rollback(() => {
              console.error("Commit Error:", err);
              return res
                .status(500)
                .json({ error: "Transaction commit failed" });
            });
          }

          res.json({ message: "Record inserted successfully" });
        });
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
  db.query(selectQuery, [userName, userId], (err, results) => {
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
        db.query(checkUsernameQuery, [newUserName], (err, userResult) => {
          if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error" });
          }

          if (userResult && userResult.length > 0) {
            return res.status(400).json({ message: "Username already exists" });
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
              db.query(
                insertQuery,
                [newUserName, newName, hashedPassword],
                (err) => {
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
            }
          );
        });
      }
    );
  });
});

/* update query */
app.post("/editJob", authenticateToken, (req, res) => {
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
    purchaseAmount,
    name,
  } = req.body;

  const convertedInDate = convertDateToSQL(inDate);
  const convertedOutDate = convertDateToSQL(outDate);

  const updateQuery = `
    UPDATE job_details 
    SET NAME = ?, MOBILE = ?, EMAIL = ?, ADDRESS = ?, ENGINEER = ?, MOC = ?, 
        IN_DATE = ?, OUT_DATE = ?, ASSETS = ?, PRODUCT_MAKE = ?, DESCRIPTION = ?, 
        SERIAL_NO = ?, FAULT_TYPE = ?, FAULT_DESC = ?, JOB_STATUS = ?, AMOUNT = ?, 
        SOLUTION_PROVIDED = ?, PURCHASE_AMOUNT=?, LAST_MODIFIED=?
    WHERE JOB_ID = ?
  `;

  const commonData = [
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
    name,
    jobID, // For the WHERE clause
  ];

  // Start transaction
  db.beginTransaction((err) => {
    if (err) {
      console.error("Error starting transaction:", err);
      return res.status(500).json({ error: "Failed to start transaction" });
    }

    // Update the job_details table
    db.query(updateQuery, commonData, (err) => {
      if (err) {
        return db.rollback(() => {
          console.error("Error updating job_details:", err);
          return res
            .status(500)
            .json({ error: "Failed to update record in job_details" });
        });
      }

      // Commit the transaction
      db.commit((err) => {
        if (err) {
          return db.rollback(() => {
            console.error("Error committing transaction:", err);
            return res
              .status(500)
              .json({ error: "Failed to commit transaction" });
          });
        }

        res.json({ message: "Record updated successfully" });
      });
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

  db.query(selectQuery, [userName, userId], (err, result) => {
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
          return res.status(500).json({ message: "Error comparing passwords" });
        }

        if (!isMatch) {
          return res.status(400).json({ message: "Old password is incorrect" });
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

            db.query(
              updateQuery,
              [hashedPassword, userName, userId],
              (err, result) => {
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
          }
        );
      }
    );
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

  db.query(selectQuery, [userName, userId], (err, result) => {
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
          return res.status(500).json({ message: "Error comparing passwords" });
        }

        if (!isMatch) {
          return res.status(400).json({ message: "Old password is incorrect" });
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

            db.query(
              updateQuery,
              [hashedPassword, userName, userId],
              (err, result) => {
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
          }
        );
      }
    );
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
    const hashedPassword = await bcrypt.hash("1234" + process.env.SALT_KEY, 10);

    // Prepare the update query
    const updateQuery = "UPDATE user SET PASSWORD = ? WHERE USERNAME = ?";

    // Execute the update query
    db.query(updateQuery, [hashedPassword, userName], (err, result) => {
      if (err) {
        console.error("Error updating password:", err);
        return res.status(500).json({ message: "Error updating password" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      res
        .status(200)
        .json({ message: `Password reset to 1234 for user - ${userName}` });
    });
  } catch (error) {
    console.error("Error hashing new password:", error);
    res.status(500).json({ message: "Error resetting password" });
  }
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
    db.query(deleteQuery, [userName], (err, result) => {
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
    db.query(deleteQuery, [JobID], (err, result) => {
      if (err) {
        console.error("Error deleting job:", err);
        return res.status(500).json({ message: "Error deleting job" });
      }

      // Check if any rows were affected
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "job not found" });
      }

      res.status(200).json({ message: `Job '${JobID}' deleted successfully.` });
    });
  } catch (error) {
    console.error("Unexpected error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

/* Start server */
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
