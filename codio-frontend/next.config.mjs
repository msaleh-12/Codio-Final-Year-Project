/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  async rewrites() {
    const apiBaseUrl = process.env.BACKEND_URL || process.env.NEXT_PUBLIC_API_URL;

    // In production, the backend must be reachable over the network.
    // The env var may point at the API base (/api/v1), so strip that suffix
    // before appending the rewrite path.
    if (!apiBaseUrl) {
      return [];
    }

    const backendOrigin = apiBaseUrl.replace(/\/api\/v1\/?$/, "");

    return [
      {
        source: '/api/v1/:path*',
        destination: `${backendOrigin}/api/v1/:path*`,
      },
    ];
  },
}

export default nextConfig
