module.exports = async (db) => {
    try {
        await db.mongoose.connect(process.env.MONGODB_URL, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        })
        
        console.log("Successfully connect to MongoDB.");
        db.initial(db.role);
    } catch (err) {
        console.error("Connection error", err);
        process.exit();
    }
}