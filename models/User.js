// models/User.js
const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    first_name: {
        type: DataTypes.STRING,
        allowNull: false
    },
    last_name: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: {
            isEmail: true
        }
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    role: {
        type: DataTypes.STRING,
        defaultValue: 'Member'
    },
    // --- 💰 NEW MEMBERSHIP FIELDS ---
    subscriptionStatus: {
        type: DataTypes.ENUM('active', 'inactive', 'past_due', 'canceled'),
        defaultValue: 'inactive'
    },
    planTier: {
        type: DataTypes.ENUM('free', 'premium'),
        defaultValue: 'free'
    },
    stripeCustomerId: {
        type: DataTypes.STRING,
        allowNull: true // Will be null until they checkout
    },
    currentPeriodEnd: {
        type: DataTypes.DATE,
        allowNull: true // When their current month expires
    }
});

module.exports = User;