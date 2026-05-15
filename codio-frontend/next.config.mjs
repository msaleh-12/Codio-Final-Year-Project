/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  async rewrites() {
    const apiUrl = process.env.BACKEND_URL || process.env.NEXT_PUBLIC_API_URL;

    // In production, the backend must be reachable over the network.
    // Localhost only works when the frontend itself is running locally.
    if (!apiUrl) {
      return [];
    }

    return [
      {
        source: '/api/v1/:path*',
        destination: `${apiUrl}/:path*`,
      },
    ];
  },
}

export default nextConfig
