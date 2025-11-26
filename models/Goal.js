// models/Goal.js (FIXED)

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database'); 

const Goal = sequelize.define('Goal', {
    description: {
        type: DataTypes.STRING,
        allowNull: true, // 🔑 FIXED: Allowing NULL on registration
    },
    status: {
        type: DataTypes.ENUM('open', 'in_progress', 'completed'),
        defaultValue: 'open',
        allowNull: false,
    },
    // The foreign key 'userId' is added automatically by the association in server.js
});

module.exports = Goal;
