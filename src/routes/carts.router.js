import { Router } from "express";
import cartsDao from "../daos/carts.dao.js";
import productsDao from "../daos/products.dao.js";

const router = Router();

router.post("/", async (req, res) => {
  try {
    const newCart = await cartsDao.createCart();
    res.json({ newCartId: newCart._id });
  } catch (error) {
    console.error("Error creating a new cart:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/", async (req, res) => {
  try {
    const cartsToRender = await cartsDao.getAllCarts();
    console.log(cartsToRender);

    const cartIds = cartsToRender.map(cart => cart._id);

    res.json({ cartIds });
  } catch (error) {
    console.error("Error getting all carts:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.get("/:cid", async (req, res) => {
  try {
    const { cid } = req.params;
    const cartWithProducts = await cartsDao.getProductsFromCart(cid);

    res.json(cartWithProducts);
    console.log(cartWithProducts);
  } catch (error) {
    console.error("Error getting cart with products:", error);
    res.status(500).json({ error: "Internal Server Error." });
  }
});

router.delete("/:cid", async (req, res) => {
  try {
    const { cid } = req.params;
    const deletedCart = await cartsDao.getCartById(cid);
    deletedCart.products = [];

    let updatedCart = await cartsDao.updateCart(cid, deletedCart);
    res.json(updatedCart);
    console.log(updatedCart);
  } catch (error) {
    console.error("Error getting cart with products:", error);
    res.status(500).json({ error: "Internal Server Error." });
  }
});

router.delete("/:cid/products/:pid", async (req, res) => {
  try {
    const { cid, pid } = req.params;
    const productId = pid;
    const quantity = req.body.quantity;
    const cartId = cid;

    const cart = await cartsDao.getCartById(cartId);

    if (cart) {
      const product = await productsDao.getProductById(productId);

      if (product) {
        const index = cart.products.findIndex((item) =>
          item.product.equals(productId)
        );

        if (index !== 1) {
          cart.products[index].quantity -= 1;
        } else {
          cart.products.splice(index, 1);
        }

        const response = await cartsDao.updateCart(cartId, cart);

        res.status(200).json({ response: "OK", message: response });
      } else {
        res.status(404).json({ error: "Product not found." });
      }
    } else {
      res.status(404).json({ error: "Cart not found." });
    }
  } catch (error) {
    console.error("Error adding product to cart:", error);
    res.status(500).json({ error: "Internal Server Error." });
  }
});

router.post("/:cid/products/:pid", async (req, res) => {
  try {
    const { cid, pid } = req.params;
    const productId = pid;
    const quantity = req.body.quantity;
    const cartId = cid;

    const cart = await cartsDao.getCartById(cartId);

    if (cart) {
      const product = await productsDao.getProductById(productId);

      if (product) {
        const index = cart.products.findIndex((item) =>
          item.product.equals(productId)
        );

        if (index !== -1) {
          cart.products[index].quantity += 1;
        } else {
          cart.products.push({ product: productId, quantity: quantity });
        }

        const response = await cartsDao.updateCart(cartId, cart);

        res.status(200).json({ response: "OK", message: response });
      } else {
        res.status(404).json({ error: "Product not found." });
      }
    } else {
      res.status(404).json({ error: "Cart not found." });
    }
  } catch (error) {
    console.error("Error adding product to cart:", error);
    res.status(500).json({ error: "Internal Server Error." });
  }
});

router.put("/:cid", async (req, res) => {
  try {
    const cid = req.params.cid;
    const cart = await cartsDao.getCartById(cid);
    const products = req.body;

    products.forEach((e) => {
      const index = cart.products.findIndex((item) => item.product.equals(cid));
      if (index != -1) {
        cart.products[index].quantity += e.quantity;
      } else {
        cart.products.push({ product: e._id, quantity: e.quantity });
      }
    });
  } catch (error) {
    console.error("Error modifiying products in cart:", error);
    res.status(500).json({ error: "Internal Server Error." });
  }
});

router.put("/:cid/products/:pid", async (req, res) => {
  try {
    const cid = req.params.cid;
    const pid = req.params.pid;
    const cart = await cartsDao.getCartById(cid);
    const product = await productsDao.getProductById(pid);

    const index = cart.products.findIndex((item) => item.product.equals(pid));

    if (index !== -1) {
      cart.products[index].quantity += req.body.quantity;
    } else {
      cart.products.push({ product: pid, quantity: req.body.quantity });
    }

    const updatedCart = await cartsDao.updateCart(cid, cart);

    res.status(200).json({ response: "OK", cart: updatedCart });
  } catch (error) {
    console.error("Error modifying products in cart:", error);
    res.status(500).json({ error: "Internal Server Error." });
  }
});

export default router;
