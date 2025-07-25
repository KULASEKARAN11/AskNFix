
// server.js (Updated)

const express = require("express");
const cors = require("cors");
const session = require("express-session");
const db = require("./database"); // Assume db pool is ready after this line

const app = express();
const PORT = 3000;

// --- Middleware Setup ---
app.use(cors({
    origin: "http://127.0.0.1:5500",
    methods: ["GET", "POST"],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: "your-staff-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 1000 * 60 * 60,
        sameSite: 'Lax'
    }
}));

// --- Helper Function ---
// (Keep your getEnhancedAppliances function here)
async function getEnhancedAppliances(roomNo, dbPool) {
    const promisePool = dbPool.promise();
    try {
        const applianceQuery = `
            SELECT a.appliance_id, a.name, ra.count AS count
            FROM room_appliance ra
            JOIN appliances a ON ra.appliance_id = a.appliance_id
            WHERE ra.roomno = ?`;
        const [totalAppliances] = await promisePool.query(applianceQuery, [roomNo]);

        const reportedCountsSql = `
            SELECT qa.appliance_id, SUM(qa.count) as reported_count
            FROM query q
            JOIN query_appliances qa ON q.QUERY_ID = qa.query_id
            WHERE q.roomno = ? AND q.status = 'not done'
            GROUP BY qa.appliance_id;`;
        const [reportedResults] = await promisePool.query(reportedCountsSql, [roomNo]);

        const reportedCountsMap = {};
        if (Array.isArray(reportedResults)) {
            reportedResults.forEach(row => {
                reportedCountsMap[row.appliance_id] = row.reported_count;
            });
        }

        const enhancedAppliances = (Array.isArray(totalAppliances) ? totalAppliances : []).map(app => {
            const reportedCount = reportedCountsMap[app.appliance_id] || 0;
            return {
                appliance_id: app.appliance_id,
                name: app.name,
                count: app.count,
                reportedCount: reportedCount
            };
        });
        return enhancedAppliances;
    } catch (error) {
        console.error(`❌ Error fetching enhanced appliances for room ${roomNo}:`, error);
        throw error;
    }
}


// --- Call Stored Procedure on Startup ---
async function runStartupProcedure() {
    try {
        if (!db || typeof db.promise !== 'function') {
             throw new Error("Database connection pool (db) or its promise() method is not available.");
        }
        const promisePool = db.promise(); // Get promise-based interface
        await promisePool.query("CALL DeleteOneByOne();");
    } catch (error) {
        console.error("❌ Error executing stored procedure 'DeleteOneByOne' during startup:", error.message);
    }
}

// Immediately call the async function during startup
// This ensures it runs once when server.js is executed
runStartupProcedure();
// --- End Procedure Call ---


// --- Route Definitions ---
app.get('/', (req, res) => {
    if (req.session.user && req.session.user.type === 'student') { // Check for student type
        if (req.session.user.residing_status === "Hosteller") {
            res.redirect('/Homepage.html');
        } else if (req.session.user.residing_status === "Day Scholar") {
            res.redirect('/Homepage1.html');
        } else {
            console.warn("Unknown residing status for logged-in student:", req.session.user.rollno);
            res.redirect('/login.html'); // Redirect students to student login
        }
    } else if (req.session.user && req.session.user.type === 'staff') { // Check for staff type
         res.redirect('/staff_dashboard.html'); // Redirect logged-in staff to their dashboard
    }
    else {
        // Default redirect can be student login or a general landing page
        res.redirect('/login.html');
    }
});

app.use(express.static(__dirname)); // Serve static files

app.get("/hostel/appliances", async (req, res) => {
    if (!req.session.user || req.session.user.residing_status !== 'Hosteller' || !req.session.user.roomno) {
        return res.status(401).json({ success: false, message: "Not logged in as a hosteller or room not assigned" });
    }

    const roomNo = req.session.user.roomno;

    try {
        const appliances = await getEnhancedAppliances(roomNo, db); // Assuming 'db' is your database connection pool
        res.json({ success: true, appliances: appliances });
    } catch (error) {
        console.error("❌ Error fetching hostel appliances:", error);
        res.status(500).json({ success: false, message: "Failed to fetch hostel appliances" });
    }
});

// (Keep /login route here)
app.post("/login", (req, res) => {
    const { rollno, password } = req.body;

    if (!rollno || !password) {
        return res.status(400).json({ success: false, message: "Missing credentials" });
    }

    const userSql = `
        SELECT s.ROLLNO, s.NAME, s.RESIDING_STATUS, ra.ROOMNO
        FROM student s
        LEFT JOIN room_allotment ra ON s.ROLLNO = ra.ROLLNO
        WHERE s.ROLLNO = ? AND s.PASSWORD = ?`;

    db.query(userSql, [rollno, password], (err, userResults) => {
        if (err) {
            console.error("❌ Database error (student fetch):", err);
            return res.status(500).json({ success: false, message: "Database error" });
        }

        if (userResults.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid student credentials" });
        }

        const user = userResults[0];

        // Common session setup function (to avoid repetition)
        const setupSessionAndRespond = (userData) => {
            req.session.user = { ...userData, type: 'student' }; // Add type identifier
            req.session.save((err) => {
                if (err) {
                    console.error("❌ Session save error:", err);
                    return res.status(500).json({ success: false, message: "Session save error" });
                }
                res.json({
                    success: true,
                    message: `Login successful (${user.RESIDING_STATUS || 'Status Unknown'})`,
                    user: req.session.user
                });
            });
        };

        if (user.RESIDING_STATUS !== 'Hosteller' || !user.ROOMNO) {
            // Day Scholar or Hosteller without assigned room yet
              const userData = {
                  rollno: user.ROLLNO,
                  name: user.NAME,
                  residing_status: user.RESIDING_STATUS,
                  roomno: user.ROOMNO, // Will be null or empty
                  roommates: [],
                  appliances: []
              };
            setupSessionAndRespond(userData);
            return;
        }

        // Hosteller with a room - Fetch details
        const currentRoomNo = user.ROOMNO;
        const roommateQuery = `
            SELECT s.ROLLNO, s.NAME, s.RESIDING_STATUS
            FROM student s
            JOIN room_allotment ra ON s.ROLLNO = ra.ROLLNO
            WHERE ra.ROOMNO = ? AND s.ROLLNO != ?`;

        db.query(roommateQuery, [currentRoomNo, user.ROLLNO], async (err, roommates) => { // Make callback async
            if (err) {
                console.error("❌ Roommate fetch error:", err);
                return res.status(500).json({ success: false, message: "Database error (roommates)" });
            }

            try {
                // Use the async helper function here
                const enhancedAppliances = await getEnhancedAppliances(currentRoomNo, db);

                const userData = {
                    rollno: user.ROLLNO,
                    name: user.NAME,
                    residing_status: user.RESIDING_STATUS,
                    roomno: currentRoomNo,
                    roommates: roommates || [],
                    appliances: enhancedAppliances
                };
                setupSessionAndRespond(userData);

            } catch (fetchError) {
                console.error("❌ Error fetching enhanced appliances during login:", fetchError);
                // Decide how to handle: maybe log in without appliance data or return error
                return res.status(500).json({ success: false, message: "Failed to load room details." });
            }
        });
    });
});


// (Keep /staff-login route here - with the isHostelStaff logic)
app.post("/staff-login", (req, res) => {
    const { staffId, password } = req.body;

    if (!staffId || !password) {
        return res.status(400).json({ success: false, message: "Missing Staff ID or Password" });
    }

    const staffSql = `
        SELECT LOGINID, NAME, role
        FROM staff
        WHERE LOGINID = ? AND PASSWORD = ?`;

    db.query(staffSql, [staffId, password], (err, staffResults) => {
        if (err) {
            console.error("❌ Database error (staff fetch):", err);
            return res.status(500).json({ success: false, message: "Database error during staff login" });
        }

        if (staffResults.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid Staff ID or Password" });
        }

        const staff = staffResults[0];
        const isHostelStaff = !staff.LOGINID.toUpperCase().includes('C');

        req.session.user = {
            id: staff.LOGINID,
            name: staff.NAME,
            role: staff.role,
            type: 'staff',
            isHostelStaff: isHostelStaff
        };

        req.session.save((err) => {
            if (err) {
                console.error("❌ Session save error (staff):", err);
                return res.status(500).json({ success: false, message: "Session save error" });
            }
            res.json({
                success: true,
                message: "Staff login successful",
                user: req.session.user,
                redirectTo: '/staff_dashboard.html'
            });
        });
    });
});

// (Keep /user route here)
app.get("/user", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Not logged in" });
    }
    res.json({ success: true, user: req.session.user });
});

// (Keep /submitQuery route here)
app.post("/submitQuery", (req, res) => {
    const { rollno, roomno, description, appliances } = req.body;

    if (!rollno || !roomno || !description || !Array.isArray(appliances) || appliances.length === 0) {
        return res.status(400).json({ success: false, message: "Missing or invalid required data." });
    }
    const hasInvalidAppliance = appliances.some(app => typeof app.appliance_id === 'undefined' || app.appliance_id === null || typeof app.count === 'undefined');
    if (hasInvalidAppliance) {
            return res.status(400).json({ success: false, message: "Invalid data within the appliances array." });
    }

    const submittedApplianceIds = appliances.map(app => app.appliance_id);

    const checkExistingSql = `
        SELECT DISTINCT qa.appliance_id, a.name FROM query q
        JOIN query_appliances qa ON q.QUERY_ID = qa.query_id JOIN appliances a ON qa.appliance_id = a.appliance_id
        WHERE q.roomno = ? AND q.status = 'not done' AND qa.appliance_id IN (?) LIMIT 1;`;

    db.query(checkExistingSql, [roomno, submittedApplianceIds], (err, existingResults) => {
        if (err) {
            console.error("❌ Database error during existing query check:", err);
            return res.status(500).json({ success: false, message: "Database error checking for existing queries." });
        }
        

        db.getConnection((err, connection) => {
            if (err) {
                console.error("❌ Error getting database connection:", err);
                return res.status(500).json({ success: false, message: "Database connection error." });
            }

            connection.beginTransaction(err => {
                if (err) {
                    console.error("❌ Error beginning transaction:", err);
                    connection.release();
                    return res.status(500).json({ success: false, message: "Failed to start database transaction." });
                }

                const getNextQueryIdSql = `SELECT IFNULL(MAX(QUERY_ID), 0) + 1 AS nextId FROM query`;
                connection.query(getNextQueryIdSql, (err, result) => {
                    if (err) {
                        console.error("❌ Error fetching next QUERY_ID:", err);
                        return connection.rollback(() => {
                            connection.release();
                            res.status(500).json({ success: false, message: "Error getting next query ID." });
                        });
                    }

                    const queryId = result[0].nextId;

                    const insertQuerySql = `INSERT INTO query (QUERY_ID, roomno, ROLLNO, description, status, raised_date, raised_time) VALUES (?, ?, ?, ?, 'not done', NOW(), NOW())`;
                    const queryValues = [queryId, roomno, rollno, description];

                    connection.query(insertQuerySql, queryValues, (err, queryResult) => {
                        if (err) {
                            console.error("❌ Error inserting into query table:", err);
                            return connection.rollback(() => {
                                connection.release();
                                res.status(500).json({ success: false, message: "Query insert failed.", detail: err.code || err.message });
                            });
                        }

                        const queryApplianceSql = `INSERT INTO query_appliances (query_id, appliance_id, count) VALUES ?`;
                        const applianceInsertValues = appliances.map(appl => [queryId, appl.appliance_id, appl.count]);

                        connection.query(queryApplianceSql, [applianceInsertValues], (err, applianceResult) => {
                            if (err) {
                                console.error("❌ Database error during query_appliances insert:", err);
                                console.error("❌ Failed values array for query_appliances:", JSON.stringify(applianceInsertValues, null, 2));
                                return connection.rollback(() => {
                                    connection.release();
                                    res.status(500).json({ success: false, message: "Appliance details insert failed.", detail: err.code || err.message });
                                });
                            }

                            connection.commit(async err => { // Make commit callback async to use await inside
                                if (err) {
                                    console.error("❌ Error committing transaction:", err);
                                    return connection.rollback(() => {
                                        connection.release();
                                        res.status(500).json({ success: false, message: "Failed to commit transaction.", detail: err.code || err.message });
                                    });
                                }
                                connection.release(); // Release connection after commit

                                try {
                                    const updatedEnhancedAppliances = await getEnhancedAppliances(roomno, db); // Use pool `db` here

                                    // Update the session data ONLY IF the user submitting is the one logged in
                                    if (req.session.user && req.session.user.rollno === rollno) {
                                         req.session.user.appliances = updatedEnhancedAppliances;
                                         req.session.save(); // Save updated session
                                    }

                                    res.json({
                                        success: true,
                                        message: "Query submitted successfully!",
                                        queryId: queryId,
                                        // Send back the potentially updated appliance list for the *current* user
                                        user: req.session.user // Send back the possibly updated user session data
                                    });
                                } catch (fetchError) {
                                    console.error("❌ Error re-fetching user data after commit:", fetchError);
                                    // Still send success for the query submission, but maybe indicate data couldn't be refreshed
                                    res.json({
                                        success: true, // Query itself succeeded
                                        message: "Query submitted successfully, but failed to refresh user data.",
                                        queryId: queryId,
                                        user: req.session.user // Send potentially stale user data
                                    });
                                }
                            }); // End commit
                        }); // End appliance insert query
                    }); // End query insert query
                }); // End getNextQueryId query
            }); // End beginTransaction
        }); // End getConnection
    }); // End Pre-check Query
});

// Route to fetch queries based on staff authorization
app.get("/api/queries", async (req, res) => {
    // 1. Authentication & Authorization Check
    if (!req.session.user || req.session.user.type !== 'staff') {
        return res.status(401).json({ success: false, message: "Unauthorized: Not logged in as staff." });
    }

    const isHostelStaff = req.session.user.isHostelStaff; // Get staff type from session

    try {
        // 2. Construct Base Query with Joins - ADD raised_date and raised_time
        let sql = `
            SELECT
                q.QUERY_ID, q.roomno, q.ROLLNO, q.description, q.status,
                q.raised_date,  -- Added raised_date
                q.raised_time,  -- Added raised_time
                r.block_id,
                qa.appliance_id, a.name AS appliance_name, qa.count AS appliance_count
            FROM query q
            JOIN room r ON q.roomno = r.roomno
            LEFT JOIN query_appliances qa ON q.QUERY_ID = qa.query_id
            LEFT JOIN appliances a ON qa.appliance_id = a.appliance_id
            WHERE q.status = 'not done'
        `;

        // 3. Add Conditional Filtering based on Staff Type
        if (isHostelStaff) {
            sql += ` AND r.block_id IN (1, 2) `; // Hostel staff see block 1 & 2
        } else {
            sql += ` AND r.block_id NOT IN (1, 2) `; // Other staff see blocks other than 1 & 2
        }

        // Order by date/time descending (latest first) - adjust if needed
        sql += ` ORDER BY q.raised_date DESC, q.raised_time DESC;`;

        // 4. Execute Query
        const promisePool = db.promise();
        const [results] = await promisePool.query(sql);

        // 5. Process Results to Group Appliances by Query ID
        const queriesMap = new Map();

        results.forEach(row => {
            if (!queriesMap.has(row.QUERY_ID)) {
                // Add new query entry to map, including date and time
                queriesMap.set(row.QUERY_ID, {
                    queryId: row.QUERY_ID,
                    roomNo: row.roomno,
                    reportedBy: row.ROLLNO, // This is the student's roll number
                    description: row.description,
                    status: row.status,
                    blockId: row.block_id,
                    raised_date: row.raised_date, // Added raised_date
                    raised_time: row.raised_time, // Added raised_time
                    appliances: []
                });
            }
            // Add appliance details if they exist for this row
            if (row.appliance_id) {
                queriesMap.get(row.QUERY_ID).appliances.push({
                    id: row.appliance_id,
                    name: row.appliance_name,
                    count: row.appliance_count
                });
            }
        });

        const processedQueries = Array.from(queriesMap.values());

        // 6. Send Response
        res.json({ success: true, queries: processedQueries });

    } catch (error) {
        console.error("❌ Database error fetching /api/queries:", error);
        res.status(500).json({ success: false, message: "Database error fetching queries." });
    }
});

// Add this route to your server file (e.g., app.js or routes file)

app.get("/api/completed-queries", async (req, res) => {
    // --- Authentication Check ---
    if (!req.session.user || !req.session.user.rollno) {
        return res.status(401).json({ success: false, message: "Unauthorized: Please log in." });
    }
    const loggedInRollno = req.session.user.rollno;

    try {
        const promisePool = db.promise(); // Use the promise wrapper from mysql2

        // --- SQL Query to fetch completed queries with details ---
        const sql = `
            SELECT
                q.QUERY_ID,
                q.ROLLNO,           -- Student who raised the query
                q.roomno,           -- Room number associated with the query
                q.description AS original_description, -- Original description from query table
                q.status,           -- Status from query table (should be 'done')
                q.raised_date,      -- When the query was originally raised
                q.raised_time,
                cq.description AS completion_description, -- Description entered by staff upon completion
                cq.staff_id, -- Staff ID from completed_queries table
                cq.completed_date,  -- Date of completion
                cq.completed_time,  -- Time of completion
                s.NAME AS completed_by_staff_name, -- Staff name from staff table
                r.block_id          -- Block ID from room table (for categorization)
            FROM
                query q
            JOIN  -- Use JOIN as a completed query MUST have an entry here
                completed_queries cq ON q.QUERY_ID = cq.query_id
            LEFT JOIN -- Use LEFT JOIN for staff in case staff record is missing or ID is wrong
                staff s ON cq.staff_id = s.LOGINID
            LEFT JOIN -- Use LEFT JOIN for room in case room details are missing
                room r ON q.roomno = r.roomno
            WHERE
                q.ROLLNO = ? AND q.status = 'done' -- Filter by logged-in student and status
            ORDER BY
                cq.completed_date DESC, cq.completed_time DESC; -- Show most recently completed first
        `;

        const [results] = await promisePool.query(sql, [loggedInRollno]);

        // --- Process results (Map to a consistent structure) ---
        const completedQueries = results.map(row => ({
            Query_id: row.QUERY_ID,
            ROLLNO: row.ROLLNO,
            room: { // Nest room details for consistency with pending queries if needed
                roomno: row.roomno,
                block_id: row.block_id
            },
            original_description: row.original_description,
            status: row.status,
            raised_date: row.raised_date,
            raised_time: row.raised_time,
            completion_description: row.completion_description,
            completed_by_staff_id: row.completed_by_staff_id,
            // Provide a default if staff name is missing
            completed_by_staff_name: row.completed_by_staff_name || (row.completed_by_staff_id ? `Staff ID: ${row.completed_by_staff_id}` : 'N/A'),
            completed_date: row.completed_date,
            completed_time: row.completed_time
            // No need to fetch appliances for completed queries based on requirements
        }));

        // --- Send Response ---
        res.json({ success: true, completedQueries: completedQueries });

    } catch (error) {
        console.error("❌ Database error fetching /api/completed-queries:", error);
        res.status(500).json({ success: false, message: "Database error fetching completed queries." });
    }
});

app.post("/api/queries/:queryId/complete", async (req, res) => {

    // Check if user is logged in and is staff
    if (!req.session.user || req.session.user.type !== 'staff') {
        return res.status(401).json({ success: false, message: "Unauthorized: Please log in as staff." });
    }

    const staffId = req.session.user.id; // Staff member completing the query
    const isHostelStaff = req.session.user.isHostelStaff; // Assumed boolean from session
    const { queryId } = req.params;
    const { description } = req.body; // Description comes from the modal

    // Validate queryId parameter
    if (!queryId || isNaN(parseInt(queryId))) {
        return res.status(400).json({ success: false, message: "Invalid or missing Query ID." });
    }
    const parsedQueryId = parseInt(queryId);

    // Validate description from body
    if (!description || typeof description !== 'string' || description.trim() === '') {
         return res.status(400).json({ success: false, message: "Completion description is required." });
    }
    const trimmedDescription = description.trim();

    let connection; // Declare connection here for access in finally block

    try {
        const promisePool = db.promise(); // Use promise wrapper for async/await

        const checkSql = `
            SELECT q.QUERY_ID, q.status, r.block_id
            FROM query q
            JOIN room r ON q.roomno = r.roomno
            WHERE q.QUERY_ID = ?
        `;
        const [checkResults] = await promisePool.query(checkSql, [parsedQueryId]);

        if (checkResults.length === 0) {
            return res.status(404).json({ success: false, message: "Query not found." }); // 404 Not Found
        }

        const queryData = checkResults[0];

        // Check if query is already marked as 'done'
        if (queryData.status !== 'not done') {
             return res.status(409).json({ success: false, message: `Query cannot be completed (current status: ${queryData.status}).` });
        }

        const queryBlockId = queryData.block_id;
        const isHostelQuery = (queryBlockId === 1 || queryBlockId === 2); // Adjust block IDs if needed


        // Apply authorization rules
        if (isHostelStaff && !isHostelQuery) {
            return res.status(403).json({ success: false, message: "Forbidden: Hostel staff cannot complete academic block queries." });
        }
        if (!isHostelStaff && isHostelQuery) {
            return res.status(403).json({ success: false, message: "Forbidden: Academic staff cannot complete hostel queries." });
        }


        connection = await promisePool.getConnection(); // Get connection from pool
        await connection.beginTransaction();

        const updateSql = `UPDATE query SET status = 'done' WHERE QUERY_ID = ?`;
        const [updateResult] = await connection.query(updateSql, [parsedQueryId]);

        if (updateResult.affectedRows === 0) {
             await connection.rollback(); // Rollback immediately
             connection.release();
             return res.status(500).json({ success: false, message: "Database error during query update." });
        }

        const insertCompletedSql = `
            INSERT INTO completed_queries (query_id, staff_id, description, completed_date, completed_time)
            VALUES (?, ?, ?, NOW(), NOW())
        `;
        const insertCompletedParams = [parsedQueryId, staffId, trimmedDescription];
        const [insertResult] = await connection.query(insertCompletedSql, insertCompletedParams);

        if (insertResult.affectedRows === 0) {
            await connection.rollback(); // Rollback immediately
            connection.release();
            return res.status(500).json({ success: false, message: "Failed to record query completion details." });
        }

        await connection.commit();

        res.json({ success: true, message: "Query marked as done successfully." });

    } catch (error) {
        console.error(`\n--- ERROR Handling /complete for Query ${parsedQueryId} ---`);
        console.error(`Error Message: ${error.message}`);
        console.error("Full Error:", error); // Log the full error object

        if (connection) {
            try {
                await connection.rollback();
            } catch (rollbackError) {
                console.error("!!! CRITICAL: FAILED TO ROLLBACK TRANSACTION !!!:", rollbackError);
            }
        } else {
        }

        res.status(500).json({ success: false, message: "An internal server error occurred." });

    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// --- NEW: API Endpoint to Get KP Gorund Floor Rooms ---
app.get("/api/rooms/kpff", async (req, res) => {
    // Optional: Authentication Check (allow any logged-in user)
    if (!req.session.user) {
         return res.status(401).json({ success: false, message: "Unauthorized: Please log in." });
    }

    try {
        const sql = "SELECT roomno FROM room WHERE block_id = 4 AND floor = 0 ORDER BY roomno ASC";
        const promisePool = db.promise();
        const [results] = await promisePool.query(sql);

        // Extract just the room numbers into an array
        const roomNumbers = results.map(row => row.roomno);

        res.json({ success: true, rooms: roomNumbers });

    } catch (error) {
        console.error("❌ Database error fetching KP Ground Floor rooms:", error);
        res.status(500).json({ success: false, message: "Database error fetching room data." });
    }
});

// --- NEW: API Endpoint to Get KP Second Floor Rooms ---
app.get("/api/rooms/kpsf", async (req, res) => { // kpsf = KP First Floor
    // Optional: Authentication Check (allow any logged-in user)
    if (!req.session.user) {
         return res.status(401).json({ success: false, message: "Unauthorized: Please log in." });
    }

    try {
        // --- CHANGE: Query for floor = 1 ---
        const sql = "SELECT roomno FROM room WHERE block_id = 4 AND floor = 1 ORDER BY roomno ASC";
        const promisePool = db.promise();
        const [results] = await promisePool.query(sql);

        // Extract just the room numbers into an array
        const roomNumbers = results.map(row => row.roomno);

        res.json({ success: true, rooms: roomNumbers });

    } catch (error) {
        console.error("❌ Database error fetching KP First Floor rooms:", error);
        res.status(500).json({ success: false, message: "Database error fetching room data." });
    }
});

app.get("/api/rooms/kptf", async (req, res) => { // kptf = KP Second Floor
    // Optional: Authentication Check (allow any logged-in user)
    if (!req.session.user) {
         return res.status(401).json({ success: false, message: "Unauthorized: Please log in." });
    }

    try {
        // --- CHANGE: Query for floor = 2 ---
        const sql = "SELECT roomno FROM room WHERE block_id = 4 AND floor = 2 ORDER BY roomno ASC";
        const promisePool = db.promise();
        const [results] = await promisePool.query(sql);

        // Extract just the room numbers into an array
        const roomNumbers = results.map(row => row.roomno);

        res.json({ success: true, rooms: roomNumbers });

    } catch (error) {
        console.error("❌ Database error fetching KP Second Floor rooms:", error);
        res.status(500).json({ success: false, message: "Database error fetching room data." });
    }
});

app.get("/api/rooms/kp4f", async (req, res) => { // kp4f = KP Fourth Floor
    // Optional: Authentication Check (allow any logged-in user)
    if (!req.session.user) {
         return res.status(401).json({ success: false, message: "Unauthorized: Please log in." });
    }

    try {
        // --- CHANGE: Query for floor = 3 ---
        const sql = "SELECT roomno FROM room WHERE block_id = 4 AND floor = 3 ORDER BY roomno ASC";
        const promisePool = db.promise();
        const [results] = await promisePool.query(sql);

        // Extract just the room numbers into an array
        const roomNumbers = results.map(row => row.roomno);

        res.json({ success: true, rooms: roomNumbers });

    } catch (error) {
        console.error("❌ Database error fetching KP Third Floor rooms:", error);
        res.status(500).json({ success: false, message: "Database error fetching room data." });
    }
});

app.get('/getKpAppliances/:roomno', async (req, res) => {
    const roomno = req.params.roomno;
    const promisePool = db.promise(); // Get the promise pool

    try {
        const applianceQuery = `
            SELECT a.appliance_id, a.name, ra.count AS count
            FROM room_appliance ra
            JOIN appliances a ON ra.appliance_id = a.appliance_id
            WHERE ra.roomno = ?`;
        const [totalAppliances] = await promisePool.query(applianceQuery, [roomno]);

        const reportedCountsSql = `
            SELECT qa.appliance_id, SUM(qa.count) as reported_count
            FROM query q
            JOIN query_appliances qa ON q.QUERY_ID = qa.query_id
            WHERE q.roomno = ? AND q.status = 'not done'
            GROUP BY qa.appliance_id;`;
        const [reportedResults] = await promisePool.query(reportedCountsSql, [roomno]);

        const reportedCountsMap = {};
        if (Array.isArray(reportedResults)) {
            reportedResults.forEach(row => {
                reportedCountsMap[row.appliance_id] = row.reported_count;
            });
        }

        const enhancedAppliances = (Array.isArray(totalAppliances) ? totalAppliances : []).map(app => {
            const reportedCount = reportedCountsMap[app.appliance_id] || 0;
            return {
                appliance_id: app.appliance_id,
                name: app.name,
                count: app.count,
                reportedCount: reportedCount
            };
        });

        res.json({ success: true, appliances: enhancedAppliances });

    } catch (error) {
        console.error(`❌ Error fetching enhanced appliances for KP room ${roomno}:`, error);
        res.status(500).json({ success: false, message: 'Failed to fetch KP appliances.' });
    }
});

// --- NEW: API Endpoint to Get Red Building Ground Floor Rooms ---
app.get("/api/rooms/red/groundfloor", async (req, res) => {
    // Optional: Authentication Check (allow any logged-in user)
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Unauthorized: Please log in." });
    }

    try {
        const sql = "SELECT roomno FROM room WHERE block_id = 3 AND floor = 0 ORDER BY roomno ASC";
        const promisePool = db.promise();
        const [results] = await promisePool.query(sql);

        // Extract just the room numbers into an array of objects
        const rooms = results.map(row => ({ roomno: row.roomno }));

        res.json({ success: true, rooms: rooms });

    } catch (error) {
        console.error("❌ Database error fetching Red Building Ground Floor rooms:", error);
        res.status(500).json({ success: false, message: "Database error fetching room data." });
    }
});

app.get("/api/rooms/red/firstfloor", async (req, res) => {
    // Optional: Authentication Check (allow any logged-in user)
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Unauthorized: Please log in." });
    }

    try {
        const sql = `
        SELECT roomno 
        FROM room 
        WHERE block_id = 3 AND floor = 1 
        ORDER BY CAST(SUBSTRING_INDEX(roomno, '-', -1) AS UNSIGNED)
        `;
        const promisePool = db.promise();
        const [results] = await promisePool.query(sql);

        // Extract just the room numbers into an array of objects
        const rooms = results.map(row => ({ roomno: row.roomno }));

        res.json({ success: true, rooms: rooms });

    } catch (error) {
        console.error("❌ Database error fetching Red Building First Floor rooms:", error);
        res.status(500).json({ success: false, message: "Database error fetching room data." });
    }
});

app.get("/api/pending-queries", async (req, res) => {
    // Authentication Check (allow any logged-in user)
    if (!req.session.user || !req.session.user.rollno) {
        return res.status(401).json({ success: false, message: "Unauthorized: Please log in." });
    }

    const loggedInRollno = req.session.user.rollno;
    runStartupProcedure();

    try {
        const promisePool = db.promise();

        // Fetch basic query information with room details, date, and time
        const querySql = `
            SELECT
                pq.Query_id,
                q.description,
                q.status,
                q.ROLLNO,
                q.roomno,
                q.raised_date,  -- Added raised_date
                q.raised_time,  -- Added raised_time
                r.block_id,
                r.roomno AS room_roomno
            FROM
                pending_queries pq
            JOIN
                query q ON pq.Query_id = q.QUERY_ID
            LEFT JOIN
                room r ON q.roomno = r.roomno
            WHERE
                q.ROLLNO = ? AND q.status = 'not done'
            ORDER BY
                q.raised_date DESC, q.raised_time DESC; -- Optional: Order by latest first
                -- OR ORDER BY pq.Query_id ASC; if you prefer original order
        `;
        const [queryResults] = await promisePool.query(querySql, [loggedInRollno]);

        const pendingQueriesWithAppliances = [];

        // Fetch appliance information for each query
        for (const query of queryResults) {
            const applianceSql = `
                SELECT
                    qa.appliance_id,
                    a.name,
                    qa.count
                FROM
                    query_appliances qa
                JOIN
                    appliances a ON qa.appliance_id = a.appliance_id
                WHERE
                    qa.query_id = ?;
            `;
            const [applianceResults] = await promisePool.query(applianceSql, [query.Query_id]);

            pendingQueriesWithAppliances.push({
                Query_id: query.Query_id,
                description: query.description,
                status: query.status,
                ROLLNO: query.ROLLNO,
                raised_date: query.raised_date, // Included date
                raised_time: query.raised_time, // Included time
                room: {
                    roomno: query.roomno,
                    block_id: query.block_id
                },
                appliances: applianceResults // Add the list of appliances
            });
        }

        res.json({ success: true, pendingQueries: pendingQueriesWithAppliances });

    } catch (error) {
        console.error("❌ Database error fetching pending queries with appliances:", error);
        res.status(500).json({ success: false, message: "Database error fetching pending queries." }); // Simplified error message
    }
});

app.post('/api/queries/:queryId/complete', async (req, res) => {
    const queryId = req.params.queryId;
    const description = req.body.description;
    console.log("Api called",queryId,description);

    if (!description) {
        return res.status(400).json({ success: false, message: "Description is required." });
    }

    try {
        const promisePool = db.promise();

        // **Start Transaction**
        await promisePool.beginTransaction();

        // 1. Update the queries table (assuming 'query_id' is the correct column name)
        const updateQuerySql = 'UPDATE queries SET status = "done" WHERE query_id = ?';
        await promisePool.query(updateQuerySql, [queryId]);

        // 2. Insert into the completed_queries table with completion timestamp
        const insertCompletedQuerySql = 'INSERT INTO completed_queries (query_id, description, completion_date) VALUES (?, ?, NOW())';
        await promisePool.query(insertCompletedQuerySql, [queryId, description]);

        // **Commit Transaction**
        await promisePool.commit();

        res.json({ success: true, message: "Query marked as done and added to completed queries." });

    } catch (error) {
        // **Rollback Transaction on Error**
        await promisePool.rollback();

        console.error("Error marking query as complete:", error);
        console.error("Database error details:", error); // Log the full error
        res.status(500).json({ success: false, message: "Error marking query as complete." });
    }
});

app.get('/api/rooms/:roomno/appliances', async (req, res) => {
    const roomno = req.params.roomno;
    const promisePool = db.promise(); // Get the promise pool

    try {
        const applianceQuery = `
            SELECT a.appliance_id, a.name, ra.count AS total_count
            FROM room_appliance ra
            JOIN appliances a ON ra.appliance_id = a.appliance_id
            WHERE ra.roomno = ?`;
        const [totalAppliances] = await promisePool.query(applianceQuery, [roomno]);

        const reportedCountsSql = `
            SELECT qa.appliance_id, SUM(qa.count) as reported_count
            FROM query q
            JOIN query_appliances qa ON q.QUERY_ID = qa.query_id
            WHERE q.roomno = ? AND q.status = 'not done'
            GROUP BY qa.appliance_id;`;
        const [reportedResults] = await promisePool.query(reportedCountsSql, [roomno]);

        const reportedCountsMap = {};
        if (Array.isArray(reportedResults)) {
            reportedResults.forEach(row => {
                reportedCountsMap[row.appliance_id] = row.reported_count;
            });
        }

        const enhancedAppliances = (Array.isArray(totalAppliances) ? totalAppliances : []).map(app => {
            const reportedCount = reportedCountsMap[app.appliance_id] || 0;
            return {
                appliance_id: app.appliance_id,
                name: app.name,
                total_count: app.total_count,
                reported_count: reportedCount
            };
        });

        res.json({ success: true, appliances: enhancedAppliances });

    } catch (error) {
        console.error(`❌ Error fetching enhanced appliances for room ${roomno}:`, error);
        res.status(500).json({ success: false, message: 'Failed to fetch appliances for this room.' });
    }
});


// --- NEW: Endpoint for Wardens/Heads to get queries they can assign ---
app.get("/api/assignable-queries", async (req, res) => {
    // 1. Authentication & Authorization Check (Warden or Head)
    if (!req.session.user || req.session.user.type !== 'staff' ||
        (req.session.user.role !== "Executive Warden" && req.session.user.role !== "College Maintenance Staff Head")) {
        return res.status(401).json({ success: false, message: "Unauthorized: Only Wardens/Heads can access this." });
    }

    const isHostelWarden = req.session.user.role === "Executive Warden"; // Determine if Hostel or College Head

    try {
        // 2. Construct Base Query (Similar to /api/queries but might need adjustments)
        // Fetch queries that are 'not done' AND not already assigned and 'not done'
        let sql = `
            SELECT
                q.QUERY_ID, q.roomno, q.ROLLNO, q.description, q.status,
                q.raised_date, q.raised_time,
                r.block_id,
                qa.appliance_id, a.name AS appliance_name, qa.count AS appliance_count,
                -- Fetch assigned staff details if assigned and not done
                aq.staff_id AS assigned_staff_id,
                s.NAME AS assigned_staff_name
            FROM query q
            JOIN room r ON q.roomno = r.roomno
            LEFT JOIN query_appliances qa ON q.QUERY_ID = qa.query_id
            LEFT JOIN appliances a ON qa.appliance_id = a.appliance_id
            -- Left join to get assignment details only if they exist and are 'not done'
            LEFT JOIN assigned_queries aq ON q.QUERY_ID = aq.query_id AND aq.status = 'not done'
            LEFT JOIN staff s ON aq.staff_id = s.LOGINID -- Join staff based on assigned_queries
            WHERE q.status = 'not done'
        `;

        // 3. Add Conditional Filtering based on Warden/Head Type
        if (isHostelWarden) {
            // Executive Warden sees Hostel blocks (1, 2)
            sql += ` AND r.block_id IN (1, 2) `;
        } else {
            // College Maintenance Head sees Academic blocks (NOT 1, 2)
            sql += ` AND r.block_id NOT IN (1, 2) `;
        }

        // Order by date/time descending
        sql += ` ORDER BY q.raised_date DESC, q.raised_time DESC;`;

        // 4. Execute Query
        const promisePool = db.promise();
        const [results] = await promisePool.query(sql);

        // 5. Process Results to Group Appliances and Filter out fully assigned ones if needed
        const queriesMap = new Map();
        results.forEach(row => {
            if (!queriesMap.has(row.QUERY_ID)) {
                queriesMap.set(row.QUERY_ID, {
                    queryId: row.QUERY_ID,
                    roomNo: row.roomno,
                    reportedBy: row.ROLLNO,
                    description: row.description,
                    status: row.status, // Should be 'not done'
                    blockId: row.block_id,
                    raised_date: row.raised_date,
                    raised_time: row.raised_time,
                    isAssigned: !!row.assigned_staff_id, // Query is assigned if assigned_staff_id is not null
                    assignedStaffId: row.assigned_staff_id, // Include staff ID
                    assignedStaffName: row.assigned_staff_name, // Include staff name
                    appliances: []
                });
            }
            // Add appliance details if they exist
            if (row.appliance_id) {
                queriesMap.get(row.QUERY_ID).appliances.push({
                    id: row.appliance_id,
                    name: row.appliance_name,
                    count: row.appliance_count
                });
            }
        });

        // Convert map values to array - potentially filter here if needed later
        const assignableQueries = Array.from(queriesMap.values());

        // 6. Send Response
        res.json({ success: true, queries: assignableQueries });

    } catch (error) {
        console.error("❌ Database error fetching /api/assignable-queries:", error);
        res.status(500).json({ success: false, message: "Database error fetching assignable queries." });
    }
});

// --- NEW: Endpoint to get available staff for assignment ---
app.get("/api/available-staff", async (req, res) => {
    // 1. Authentication & Authorization Check (Warden or Head)
    if (!req.session.user || req.session.user.type !== 'staff' ||
        (req.session.user.role !== "Executive Warden" && req.session.user.role !== "College Maintenance Staff Head")) {
        return res.status(401).json({ success: false, message: "Unauthorized: Only Wardens/Heads can access this." });
    }

    const isHostelWarden = req.session.user.role === "Executive Warden";

    try {
        // 2. Base SQL to select staff
        let staffSql = `
            SELECT s.LOGINID, s.NAME, s.role
            FROM staff s
            WHERE
                -- Exclude the wardens/heads themselves
                s.role NOT IN ('Executive Warden', 'College Maintenance Staff Head')
                -- Exclude staff who currently have ANY 'not done' assignment
                AND s.LOGINID NOT IN (
                    SELECT aq.staff_id
                    FROM assigned_queries aq
                    WHERE aq.status = 'not done'
                )
        `;

        // 3. Filter staff based on the domain (Hostel vs College)
        if (isHostelWarden) {
            // Hostel Warden assigns to staff whose LOGINID does NOT contain 'C' (assuming 'C' means College)
            staffSql += ` AND s.LOGINID NOT LIKE '%C%' `;
        } else {
            // College Head assigns to staff whose LOGINID contains 'C'
            staffSql += ` AND s.LOGINID LIKE '%C%' `;
        }

        staffSql += ` ORDER BY s.NAME ASC;`;

        // 4. Execute Query
        const promisePool = db.promise();
        const [staffResults] = await promisePool.query(staffSql);

        // 5. Format results (optional, could just send staffResults)
        const availableStaff = staffResults.map(staff => ({
            id: staff.LOGINID,
            name: staff.NAME,
            role: staff.role
        }));

        // 6. Send Response
        res.json({ success: true, staff: availableStaff });

    } catch (error) {
        console.error("❌ Database error fetching /api/available-staff:", error);
        res.status(500).json({ success: false, message: "Database error fetching available staff." });
    }
});

// --- NEW: Endpoint to assign a query to a staff member ---
app.post("/api/assign-query", async (req, res) => {
    // 1. Authentication & Authorization Check (Warden or Head)
    if (!req.session.user || req.session.user.type !== 'staff' ||
        (req.session.user.role !== "Executive Warden" && req.session.user.role !== "College Maintenance Staff Head")) {
        return res.status(401).json({ success: false, message: "Unauthorized: Only Wardens/Heads can assign queries." });
    }

    const { queryId, staffId } = req.body;

    // 2. Validation
    if (!queryId || !staffId || isNaN(parseInt(queryId)) || typeof staffId !== 'string') {
        return res.status(400).json({ success: false, message: "Missing or invalid Query ID or Staff ID." });
    }
    const parsedQueryId = parseInt(queryId);

    let connection;
    try {
        const promisePool = db.promise();
        connection = await promisePool.getConnection();
        await connection.beginTransaction();

        // 3. Check if the query exists and is 'not done'
        const checkQuerySql = "SELECT status FROM query WHERE QUERY_ID = ? FOR UPDATE"; // Lock row
        const [queryResults] = await connection.query(checkQuerySql, [parsedQueryId]);
        if (queryResults.length === 0 || queryResults[0].status !== 'not done') {
            await connection.rollback();
            connection.release();
            return res.status(404).json({ success: false, message: "Query not found or already completed." });
        }

        // 4. Check if the staff exists and is eligible (optional but good practice)
        //    (Could reuse logic from /api/available-staff if needed, but simpler check here)
        const checkStaffSql = "SELECT LOGINID FROM staff WHERE LOGINID = ?";
        const [staffResults] = await connection.query(checkStaffSql, [staffId]);
        if (staffResults.length === 0) {
            await connection.rollback();
            connection.release();
            return res.status(404).json({ success: false, message: "Selected staff member not found." });
        }

        // 5. Check if this specific assignment already exists and is 'not done'
        const checkExistingAssignmentSql = `
            SELECT query_id FROM assigned_queries
            WHERE query_id = ? AND staff_id = ? AND status = 'not done'
        `;
        const [existingAssignment] = await connection.query(checkExistingAssignmentSql, [parsedQueryId, staffId]);
        if (existingAssignment.length > 0) {
            await connection.rollback();
            connection.release();
            return res.status(409).json({ success: false, message: "This query is already assigned to this staff member and is pending." }); // 409 Conflict
        }

        // 6. Insert into assigned_queries table
        const insertSql = `
            INSERT INTO assigned_queries (query_id, staff_id, status, assigned_date, assigned_time)
            VALUES (?, ?, 'not done', CURDATE(), CURTIME())
        `;
        const [insertResult] = await connection.query(insertSql, [parsedQueryId, staffId]);

        if (insertResult.affectedRows === 0) {
            await connection.rollback();
            connection.release();
            return res.status(500).json({ success: false, message: "Failed to assign query." });
        }

        // 7. Commit Transaction
        await connection.commit();
        connection.release();

        // 8. Send Success Response
        res.json({ success: true, message: `Query ${parsedQueryId} assigned to staff ${staffId} successfully.` });

    } catch (error) {
        console.error("❌ Database error during /api/assign-query:", error);
        if (connection) {
            try { await connection.rollback(); } catch (rbError) { console.error("Rollback failed:", rbError); }
            connection.release();
        }
        // Handle potential duplicate key errors if unique constraint exists
        if (error.code === 'ER_DUP_ENTRY') {
             return res.status(409).json({ success: false, message: "Assignment failed: Possible duplicate entry." });
        }
        res.status(500).json({ success: false, message: "Database error during query assignment." });
    }
});


// --- NEW: Endpoint for staff to get their assigned queries ---
app.get("/api/my-assigned-queries", async (req, res) => {
    // 1. Authentication Check
    if (!req.session.user || req.session.user.type !== 'staff') {
        return res.status(401).json({ success: false, message: "Unauthorized: Please log in as staff." });
    }
    const loggedInStaffId = req.session.user.id;

    try {
        // 2. SQL Query to fetch assigned queries with details
        const sql = `
            SELECT
                q.QUERY_ID, q.roomno, q.ROLLNO AS reported_by, q.description,
                q.raised_date, q.raised_time,
                aq.assigned_date, aq.assigned_time,
                r.block_id,
                qa.appliance_id, a.name AS appliance_name, qa.count AS appliance_count
            FROM assigned_queries aq
            JOIN query q ON aq.query_id = q.QUERY_ID
            JOIN room r ON q.roomno = r.roomno
            LEFT JOIN query_appliances qa ON q.QUERY_ID = qa.query_id
            LEFT JOIN appliances a ON qa.appliance_id = a.appliance_id
            WHERE aq.staff_id = ? AND aq.status = 'not done' AND q.status = 'not done' -- Ensure both statuses are pending
            ORDER BY aq.assigned_date DESC, aq.assigned_time DESC;
        `;

        // 3. Execute Query
        const promisePool = db.promise();
        const [results] = await promisePool.query(sql, [loggedInStaffId]);

        // 4. Process Results (Group appliances)
        const queriesMap = new Map();
        results.forEach(row => {
            if (!queriesMap.has(row.QUERY_ID)) {
                queriesMap.set(row.QUERY_ID, {
                    queryId: row.QUERY_ID,
                    roomNo: row.roomno,
                    reportedBy: row.reported_by,
                    description: row.description,
                    raisedDate: row.raised_date,
                    raisedTime: row.raised_time,
                    assignedDate: row.assigned_date,
                    assignedTime: row.assigned_time,
                    blockId: row.block_id,
                    appliances: []
                });
            }
            // Add appliance details if they exist
            if (row.appliance_id) {
                queriesMap.get(row.QUERY_ID).appliances.push({
                    id: row.appliance_id,
                    name: row.appliance_name,
                    count: row.appliance_count
                });
            }
        });

        const assignedQueries = Array.from(queriesMap.values());

        // 5. Send Response
        res.json({ success: true, queries: assignedQueries });

    } catch (error) {
        console.error("❌ Database error fetching /api/my-assigned-queries:", error);
        res.status(500).json({ success: false, message: "Database error fetching assigned queries." });
    }
});


// --- NEW: Endpoint for staff to mark their OWN assigned query as complete ---
app.post("/api/assigned-queries/:queryId/complete", async (req, res) => {
    // 1. Authentication Check (Must be logged-in staff)
    if (!req.session.user || req.session.user.type !== 'staff') {
        return res.status(401).json({ success: false, message: "Unauthorized: Please log in as staff." });
    }
    const loggedInStaffId = req.session.user.id;
    const { queryId } = req.params;
    const { description } = req.body;

    // 2. Validation
    if (!queryId || isNaN(parseInt(queryId))) {
        return res.status(400).json({ success: false, message: "Invalid or missing Query ID." });
    }
    const parsedQueryId = parseInt(queryId);
    if (!description || typeof description !== 'string' || description.trim() === '') {
        return res.status(400).json({ success: false, message: "Completion description is required." });
    }
    const trimmedDescription = description.trim();

    let connection;
    try {
        const promisePool = db.promise();
        connection = await promisePool.getConnection();
        await connection.beginTransaction();

        // 3. Verify the query exists, is assigned to THIS staff, and both are 'not done'
        const checkSql = `
            SELECT q.status AS query_status, aq.status AS assignment_status
            FROM query q
            JOIN assigned_queries aq ON q.QUERY_ID = aq.query_id
            WHERE q.QUERY_ID = ? AND aq.staff_id = ?
            FOR UPDATE; -- Lock rows for update
        `;
        const [checkResults] = await connection.query(checkSql, [parsedQueryId, loggedInStaffId]);

        if (checkResults.length === 0) {
            await connection.rollback();
            connection.release();
            return res.status(404).json({ success: false, message: "Query not found or not assigned to you." });
        }

        const { query_status, assignment_status } = checkResults[0];

        if (query_status !== 'not done' || assignment_status !== 'not done') {
            await connection.rollback();
            connection.release();
             // 409 Conflict is appropriate here
            return res.status(409).json({ success: false, message: "Query or assignment is already marked as done." });
        }

        // 4. Update query table status
        const updateQuerySql = `UPDATE query SET status = 'done' WHERE QUERY_ID = ?`;
        const [updateQueryResult] = await connection.query(updateQuerySql, [parsedQueryId]);
        if (updateQueryResult.affectedRows === 0) {
             throw new Error("Failed to update query status."); // Will trigger rollback
        }

        // 5. Update assigned_queries table status
        const updateAssignmentSql = `UPDATE assigned_queries SET status = 'done' WHERE query_id = ? AND staff_id = ?`;
        const [updateAssignmentResult] = await connection.query(updateAssignmentSql, [parsedQueryId, loggedInStaffId]);
         if (updateAssignmentResult.affectedRows === 0) {
             throw new Error("Failed to update assignment status."); // Will trigger rollback
        }

        // 6. Insert into completed_queries table
        const insertCompletedSql = `
            INSERT INTO completed_queries (query_id, staff_id, description, completed_date, completed_time)
            VALUES (?, ?, ?, CURDATE(), CURTIME())
        `;
        const [insertResult] = await connection.query(insertCompletedSql, [parsedQueryId, loggedInStaffId, trimmedDescription]);
        if (insertResult.affectedRows === 0) {
            throw new Error("Failed to insert into completed_queries."); // Will trigger rollback
        }

        // 7. Commit Transaction
        await connection.commit();
        connection.release();

        // 8. Send Success Response
        res.json({ success: true, message: "Query marked as completed successfully." });

    } catch (error) {
        console.error(`❌ Database error during /api/assigned-queries/${queryId}/complete:`, error);
        if (connection) {
            try { await connection.rollback(); } catch (rbError) { console.error("Rollback failed:", rbError); }
            connection.release();
        }
        res.status(500).json({ success: false, message: `Database error completing query: ${error.message}` });
    }
});


// --- NEW: Endpoint for Wardens/Heads to view completed queries in their domain ---
app.get("/completed-queries-staff", async (req, res) => {
    // 1. Authentication & Authorization Check
    if (!req.session.user || req.session.user.type !== 'staff' ||
        (req.session.user.role !== "Executive Warden" && req.session.user.role !== "College Maintenance Staff Head")) {
        return res.status(401).json({ success: false, message: "Unauthorized: Only Wardens/Heads can access this." });
    }

    const userRole = req.session.user.role;
    const isHostelWarden = userRole === "Executive Warden";

    try {
        const promisePool = db.promise();

        // 2. Base SQL Query
        let sql = `
            SELECT
                cq.query_id,
                q.ROLLNO AS student_id,
                q.roomno AS location,
                q.description AS issue_type, -- Assuming original description indicates issue type broadly
                cq.description AS remarks, -- Staff completion remarks
                q.raised_date AS raised_at_date,
                q.raised_time AS raised_at_time,
                cq.completed_date AS completed_at_date,
                cq.completed_time AS completed_at_time,
                cq.staff_id AS completed_by_staff_id,
                s.NAME AS completed_by_staff_name, -- Added staff name
                r.block_id
            FROM completed_queries cq
            JOIN query q ON cq.query_id = q.QUERY_ID
            JOIN room r ON q.roomno = r.roomno
            LEFT JOIN staff s ON cq.staff_id = s.LOGINID -- Join with staff table
            WHERE q.status = 'done' -- Ensure we only get queries marked as done
        `;

        // 3. Add Role-Based Filtering
        if (isHostelWarden) {
            // Executive Warden sees Hostel blocks (1, 2)
            sql += ` AND r.block_id IN (1, 2) `;
        } else {
            // College Maintenance Head sees Academic blocks (NOT 1, 2)
            sql += ` AND r.block_id NOT IN (1, 2) `;
        }

        // 4. Order Results
        sql += ` ORDER BY cq.completed_date DESC, cq.completed_time DESC;`;

        // 5. Execute Query
        const [results] = await promisePool.query(sql);

        // 6. Format Results (Combine date and time)
        const formattedQueries = results.map(row => ({
            query_id: row.query_id,
            student_id: row.student_id,
            location: row.location,
            issue_type: row.issue_type, // You might want a more specific field if available
            description: row.issue_type, // Using original description as description field for now
            raised_at: new Date(`${row.raised_at_date.toISOString().split('T')[0]}T${row.raised_at_time}`),
            completed_at: new Date(`${row.completed_at_date.toISOString().split('T')[0]}T${row.completed_at_time}`),
            completed_by_staff_id: row.completed_by_staff_id,
            completed_by_staff_name: row.completed_by_staff_name || 'N/A', // Include staff name
            remarks: row.remarks
        }));

        // 7. Send Response
        res.json({ success: true, queries: formattedQueries });

    } catch (error) {
        console.error("❌ Database error fetching /completed-queries-staff:", error);
        res.status(500).json({ success: false, message: "Database error fetching completed queries for staff." });
    }
});


// (Keep /logout route here)
app.post("/logout", (req, res) => {
    const userName = req.session.user ? (req.session.user.name || req.session.user.id) : 'User';
    req.session.destroy((err) => {
        if (err) {
            console.error("❌ Logout failed:", err);
            return res.status(500).json({ success: false, message: "Logout failed" });
        }
        res.clearCookie("connect.sid");
        res.json({ success: true, message: "Logged out successfully" });
    });
});


// --- 404 Handler ---
app.use((req, res) => {
    res.status(404).json({ success: false, message: "Route not found" });
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
