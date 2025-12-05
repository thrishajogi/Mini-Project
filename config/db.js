const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    // Connect to MongoDB
    const conn = await mongoose.connect('mongodb://127.0.0.1:27017/zerobankDB', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000 // 5 second timeout
    });

    console.log(`MongoDB Connected: ${conn.connection.host}`);
    return true;

  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1); // Exit with failure
  }
};

// Test the connection
const testConnection = async () => {
  try {
    await connectDB();
    console.log('Database connection test successful');
  } catch (err) {
    console.error('Database connection test failed:', err);
  }
};

// Export both functions
module.exports = {
  connectDB,
  testConnection
};
