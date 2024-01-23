import { mongoose, Schema, model } from "mongoose";

const cartSchema = new Schema({
  products: {
    type: [
      {
        product: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "products",
        },
        quantity:{
          type:Number,
          default:1
        },
      },
    ],
  },
});

cartSchema.pre("findOne", function () {
  this.populate("products.product");
});

const cartModel = model("carts", cartSchema);

export { cartModel };
