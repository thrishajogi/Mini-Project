const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(
      "mongodb+srv://shettymadhura26_db_user:5nDlwTroTCJFMC7X@cluster0.snkj9jx.mongodb.net/zerobank?retryWrites=true&w=majority"
    );
    console.log("MongoDB Connected");
  } catch (err) {
    console.error("MongoDB Error:", err);
    process.exit(1);
  }
};

module.exports = connectDB;
