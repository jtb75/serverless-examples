const { Sequelize, DataTypes, QueryTypes } = require('sequelize');

// SECURITY VULNERABILITY: SQL Injection in Sequelize Queries
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
//
// This Lambda function demonstrates multiple SQL injection vulnerabilities
// when using Sequelize ORM with raw queries and improper parameter handling.

// Initialize Sequelize (SQLite for demo, but vulnerability applies to any DB)
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: '/tmp/vulnerable.db',
    logging: false
});

// Define User model
const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: DataTypes.STRING,
    email: DataTypes.STRING,
    role: DataTypes.STRING
});

exports.handler = async (event) => {
    /**
     * AWS Lambda function with multiple SQL injection vulnerabilities
     *
     * VULNERABILITIES:
     * 1. Raw query with string concatenation (CRITICAL)
     * 2. Sequelize.literal() with user input (CRITICAL)
     * 3. Order by clause injection
     * 4. WHERE clause with template literals
     */

    try {
        await sequelize.sync();
        const body = JSON.parse(event.body || '{}');
        const action = body.action;

        // VULNERABILITY 1: Raw SQL query with string concatenation
        // CWE-89: SQL Injection via raw query
        if (action === 'search') {
            const searchTerm = body.search;

            // DANGEROUS: Direct string concatenation in raw query
            const results = await sequelize.query(
                `SELECT * FROM Users WHERE username LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%'`,
                { type: QueryTypes.SELECT }
            );

            return {
                statusCode: 200,
                body: JSON.stringify({ users: results })
            };
        }

        // VULNERABILITY 2: SQL Injection via Sequelize.literal()
        // CWE-89: Improper use of literal() with user input
        if (action === 'filter') {
            const filterCondition = body.filter;

            // DANGEROUS: User input passed directly to Sequelize.literal()
            const users = await User.findAll({
                where: Sequelize.literal(filterCondition)
            });

            return {
                statusCode: 200,
                body: JSON.stringify({ users })
            };
        }

        // VULNERABILITY 3: Order by clause injection
        // CWE-89: SQL Injection in ORDER BY clause
        if (action === 'list') {
            const orderBy = body.orderBy || 'username';
            const direction = body.direction || 'ASC';

            // DANGEROUS: User-controlled order clause
            const users = await sequelize.query(
                `SELECT * FROM Users ORDER BY ${orderBy} ${direction}`,
                { type: QueryTypes.SELECT }
            );

            return {
                statusCode: 200,
                body: JSON.stringify({ users })
            };
        }

        // VULNERABILITY 4: Template literal in where clause
        // CWE-89: SQL Injection via template string
        if (action === 'getByRole') {
            const role = body.role;

            // DANGEROUS: Template literal without parameterization
            const users = await User.findAll({
                where: Sequelize.literal(`role = '${role}'`)
            });

            return {
                statusCode: 200,
                body: JSON.stringify({ users })
            };
        }

        // VULNERABILITY 5: Dynamic column selection
        // CWE-89: SQL Injection via column names
        if (action === 'getColumn') {
            const column = body.column;
            const value = body.value;

            // DANGEROUS: User-controlled column name
            const results = await sequelize.query(
                `SELECT * FROM Users WHERE ${column} = '${value}'`,
                { type: QueryTypes.SELECT }
            );

            return {
                statusCode: 200,
                body: JSON.stringify({ results })
            };
        }

        return {
            statusCode: 400,
            body: JSON.stringify({ error: 'Invalid action' })
        };

    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: error.message })
        };
    }
};
