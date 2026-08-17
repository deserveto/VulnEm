/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  images: {
    remotePatterns: [{ protocol: "https", hostname: process.env.IMAGE_CDN_HOST || "cdn.example.com" }],
  },
};

module.exports = nextConfig;
