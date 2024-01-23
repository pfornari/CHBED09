import { Schema, model } from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2";

let productModel;

try {
  productModel = model("products");
} catch {
  const productSchema = new Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true },
    thumbnail: { type: String, required: true },
    code: { type: String, required: true, unique: true },
    stock: { type: Number, required: true },
    status: { type: Boolean, default: true },
    category: { type: String, required: true, index: true },
  });

  productSchema.plugin(mongoosePaginate);
  productModel = model("products", productSchema);
}

export { productModel };
