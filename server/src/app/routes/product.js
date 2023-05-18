const express = require("express");
const router = express.Router();
const product = require("../controllers/product/product.controller");
const { authJWT } = require("../middlewares");

router.get("/getAllProduct/", product.getAllProduct);
router.post(
  "/createProduct",
  [authJWT.verifyToken, authJWT.isAdmin],
  product.createProduct
);
router.get("/:id", product.getById);
router.put(
  "/:id",
  [authJWT.verifyToken, authJWT.isAdmin],
  product.updateProduct
);
router.delete(
  "/:id",
  [authJWT.verifyToken, authJWT.isAdmin],
  product.deleteProduct
);

module.exports = router;
