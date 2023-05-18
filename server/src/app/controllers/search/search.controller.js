const db = require('../../data');
const product = db.product;

class SearchController {
    // [Get] /api/search/items?keyword=
    getItem = (req, res) => {
        const keyWord = req.query.keyword;
        if (keyWord != "") {
            product.find({ name: { $regex: keyWord, $options: 'i' } })
                .then(results => res.json(results.map(result => result.toClient())))
                .catch((err) => {
                    res.status(500).send({ message: err });
                })
        }
        else {
            res.json([]);
        }
    }
}

module.exports = new SearchController;