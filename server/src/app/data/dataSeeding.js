
module.exports = function initial(Role) {
    Role.estimatedDocumentCount((err, count) => {
        if (!err && count === 0) {
            console.log("Start adding roles...");
            new Role({
                name: "user"
            }).save(err => {
                if (err) {
                console.log("error", err);
                }
                console.log("Added 'user' to roles collection");
            });
            new Role({
                name: "admin"
            }).save(err => {
                if (err) {
                console.log("error", err);
                }
                console.log("Added 'admin' to roles collection");
            });
            console.log("Adding roles finished!");
        }
    });
}