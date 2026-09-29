const path = require("path");

module.exports = {
  paths: {
    appIndexJs: path.resolve(__dirname, "index.js"),
    appHtml: path.resolve(__dirname, "public", "index.html"),
    appSrc: path.resolve(__dirname),
  },
  webpack: {
    alias: {
      "@": path.resolve(__dirname),
    },
  },
};
