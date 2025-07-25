
const mysql = require("mysql2");

const dbConfig = {
    host: "127.0.0.1",
    port: 3306,
    user: "root",
    password: "javaproject@6",
    database: "dbms_project",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

pool.getConnection((err, connection) => {
    if (err) {
        console.error("❌ Database Pool Creation Error or Initial Connection Failed:", err.message);
    } else {
        console.log("✅ Database Pool created & initial connection successful!");
        connection.release();
    }
});

module.exports = pool;