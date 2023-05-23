const path = require("path");
const { SubresourceIntegrityPlugin } = require("webpack-subresource-integrity");
const WebpackAssetsManifest = require("webpack-assets-manifest");
const CopyPlugin = require("copy-webpack-plugin");
const HtmlWebpackPlugin = require("html-webpack-plugin");
const WasmPackPlugin = require("@wasm-tool/wasm-pack-plugin");
const dist = path.resolve(__dirname, "dist");

module.exports = {
  mode: "production",
  entry: {
    app: {
      import: "./js/app.js",
      chunkLoading: false
  }
  },
  output: {
    path: dist,
    filename: "[name].[contenthash].js"
  },
  experiments: {
    asyncWebAssembly: true
  },
  module: {
    rules: [
      {
        test: /\.js$/i,
        include: path.resolve(__dirname, "js"),
        use: {
          loader: "babel-loader",
          options: { presets: ["@babel/preset-env"] },
        },
      },
      {
        test: /\.css$/i,
        include: path.resolve(__dirname, "css"),
        use: [
          "style-loader", 
          "css-loader", 
          "postcss-loader"
        ],
      },
    ],
  },
  devServer: {
    contentBase: dist,
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        {
          from: path.resolve(__dirname, "assets"),
          to: dist
        }
      ]
    }),
    
    new SubresourceIntegrityPlugin({
          hashFuncNames: ["sha384", "sha512"],
          enabled: true,
        }),
    
    new WebpackAssetsManifest({ integrity: true }),    

    new WasmPackPlugin({
      crateDirectory: __dirname,
    }),
    
    new HtmlWebpackPlugin({
      filename: "frame.html",
      title: "hcc frame",
      hash: true
    }),
  ]
};
