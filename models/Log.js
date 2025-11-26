// models/Log.js (FINAL FIXED VERSION)

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database'); 

const Log = sequelize.define('Log', {
    date: {
        type: DataTypes.DATEONLY, 
        allowNull: true, // 🔑 FIXED: Allowing NULL for new users
        defaultValue: DataTypes.NOW 
    },
    exercise: {
        type: DataTypes.STRING,
        allowNull: true, // 🔑 FIXED: Allowing NULL for new users
    },
    weight: {
        type: DataTypes.INTEGER,
        allowNull: true,
        defaultValue: 0 
    },
    reps: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0
    },
    sets: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0
    },
    // The foreign key 'userId' will be added automatically by the association
});

module.exports = Log;
