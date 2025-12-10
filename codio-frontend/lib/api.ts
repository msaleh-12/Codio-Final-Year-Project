const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

// Token management functions
export function getAccessToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('codio_access_token');
}

export function getRefreshToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('codio_refresh_token');
}

export function setTokens(accessToken: string, refreshToken: string): void {
  if (typeof window === 'undefined') return;
  console.log('[API] Storing authentication tokens');
  localStorage.setItem('codio_access_token', accessToken);
  localStorage.setItem('codio_refresh_token', refreshToken);
  console.log('[API] Tokens stored successfully');
}

export function clearTokens(): void {
  if (typeof window === 'undefined') return;
  console.log('[API] Clearing authentication tokens');
  localStorage.removeItem('codio_access_token');
  localStorage.removeItem('codio_refresh_token');
  console.log('[API] Tokens cleared');
}

export async function refreshAccessToken(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  
  if (!refreshToken) {
    console.error('[API] No refresh token available');
    return false;
  }
  
  try {
    console.log('[API] Attempting to refresh access token');
    const response = await fetch(`${API_URL}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    
    if (!response.ok) {
      console.error('[API] Token refresh failed:', response.status);
      clearTokens();
      return false;
    }
    
    const data = await response.json();
    
    if (data.success && data.access_token) {
      localStorage.setItem('codio_access_token', data.access_token);
      console.log('[API] Access token refreshed successfully');
      return true;
    }
    
    console.error('[API] Token refresh failed: Invalid response');
    return false;
  } catch (error) {
    console.error('[API] Token refresh error:', error);
    return false;
  }
}

export async function fetchFromAPI(endpoint: string, options: RequestInit = {}, retryOnAuthError = true) {
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const url = `${API_URL}${endpoint}`;
  
  console.log(`[API] [${requestId}] Starting API request`);
  console.log(`[API] [${requestId}] Method: ${options.method || 'GET'}`);
  console.log(`[API] [${requestId}] URL: ${url}`);
  console.log(`[API] [${requestId}] Full endpoint: ${endpoint}`);
  
  // Add JWT token to headers if available
  const accessToken = getAccessToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };
  
  if (accessToken) {
    console.log(`[API] [${requestId}] Adding Authorization header`);
    headers['Authorization'] = `Bearer ${accessToken}`;
  } else {
    console.log(`[API] [${requestId}] No access token available`);
  }
  
  if (options.body) {
    console.log(`[API] [${requestId}] Request body:`, JSON.parse(options.body as string));
  }
  
  console.log(`[API] [${requestId}] Sending fetch request...`);
  const startTime = Date.now();
  
  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });
    
    const duration = Date.now() - startTime;
    console.log(`[API] [${requestId}] Response received in ${duration}ms`);
    console.log(`[API] [${requestId}] Status: ${response.status} ${response.statusText}`);
    console.log(`[API] [${requestId}] OK: ${response.ok}`);

    // Handle 401 Unauthorized - try to refresh token only if we have a token
    if (response.status === 401 && retryOnAuthError) {
      const hasToken = getAccessToken();
      
      // Only try to refresh if we actually have a token (authenticated request)
      if (hasToken) {
        console.log(`[API] [${requestId}] 401 Unauthorized, attempting token refresh`);
        const refreshed = await refreshAccessToken();
        
        if (refreshed) {
          console.log(`[API] [${requestId}] Token refreshed, retrying request`);
          return fetchFromAPI(endpoint, options, false); // Retry once without recursion
        } else {
          console.error(`[API] [${requestId}] Token refresh failed, clearing session`);
          clearTokens();
          throw new Error('Session expired. Please login again.');
        }
      }
      // If no token, it's a login failure, let it fall through to normal error handling
    }

    if (!response.ok) {
      console.log(`[API] [${requestId}] Response not OK, parsing error...`);
      const errorData = await response.json().catch(() => ({}));
      console.error(`[API] [${requestId}] Error data:`, errorData);
      const errorMsg = errorData.error || `API Error: ${response.statusText}`;
      console.error(`[API] [${requestId}] Throwing error: ${errorMsg}`);
      throw new Error(errorMsg);
    }

    console.log(`[API] [${requestId}] Parsing successful response JSON...`);
    const data = await response.json();
    console.log(`[API] [${requestId}] Response data:`, data);
    console.log(`[API] [${requestId}] Request completed successfully`);
    return data;
  } catch (error: any) {
    const duration = Date.now() - startTime;
    console.error(`[API] [${requestId}] Request failed after ${duration}ms`);
    console.error(`[API] [${requestId}] Error type: ${error?.name}`);
    console.error(`[API] [${requestId}] Error message: ${error?.message}`);
    console.error(`[API] [${requestId}] Full error:`, error);
    throw error;
  }
}

export const api = {
  // Playlist endpoints
  getPlaylistVideos: (playlistUrl: string) => {
    console.log(`[API] getPlaylistVideos called with URL: ${playlistUrl}`);
    return fetchFromAPI('/api/v1/playlist/videos', {
      method: 'POST',
      body: JSON.stringify({ playlist_url: playlistUrl }),
    });
  },

  // Video endpoints
  processVideo: (youtubeUrl: string) => {
    console.log(`[API] processVideo called with URL: ${youtubeUrl}`);
    return fetchFromAPI('/api/v1/video/process', {
      method: 'POST',
      body: JSON.stringify({ youtube_url: youtubeUrl }),
    });
  },

  getVideoInfo: (videoId: string) => {
    console.log(`[API] getVideoInfo called for video: ${videoId}`);
    return fetchFromAPI(`/api/v1/video/${videoId}/info`);
  },

  getVideoStatus: (videoId: string) => {
    console.log(`[API] getVideoStatus called for video: ${videoId}`);
    return fetchFromAPI(`/api/v1/video/${videoId}/status`);
  },

  cancelVideoProcessing: (videoId: string) => {
    console.log(`[API] cancelVideoProcessing called for video: ${videoId}`);
    return fetchFromAPI(`/api/v1/video/${videoId}/cancel`, {
      method: 'POST',
    });
  },

  getCodeAtTimestamp: (videoId: string, timestamp: number) => {
    console.log(`[API] getCodeAtTimestamp called - video: ${videoId}, timestamp: ${timestamp}s`);
    return fetchFromAPI(`/api/v1/video/${videoId}/code?timestamp=${timestamp}`);
  },

  getFrameAtTimestamp: (videoId: string, timestamp: number) => {
    console.log(`[API] getFrameAtTimestamp called - video: ${videoId}, timestamp: ${timestamp}s`);
    return fetchFromAPI(`/api/v1/video/${videoId}/frame?timestamp=${timestamp}`);
  },

  getAllSegments: (videoId: string) => {
    console.log(`[API] getAllSegments called for video: ${videoId}`);
    return fetchFromAPI(`/api/v1/video/${videoId}/segments`);
  },

  getStats: () => {
    console.log(`[API] getStats called`);
    return fetchFromAPI('/api/v1/stats');
  },

  // User and playlist management
  userLogin: (email: string, name: string) => {
    console.log(`[API] userLogin called for: ${email}`);
    return fetchFromAPI('/api/v1/user/login', {
      method: 'POST',
      body: JSON.stringify({ email, name }),
    });
  },

  // Authentication endpoints
  signup: (email: string, name: string, password: string) => {
    console.log(`[API] signup called for: ${email}`);
    return fetchFromAPI('/api/v1/auth/signup', {
      method: 'POST',
      body: JSON.stringify({ email, name, password }),
    });
  },

  login: (email: string, password: string) => {
    console.log(`[API] login called for: ${email}`);
    return fetchFromAPI('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  getUserPlaylists: (email: string) => {
    console.log(`[API] getUserPlaylists called for: ${email}`);
    return fetchFromAPI(`/api/v1/user/${encodeURIComponent(email)}/playlists`);
  },

  saveUserPlaylist: (userEmail: string, playlistId: string, playlistUrl: string, playlistTitle: string, totalVideos: number) => {
    console.log(`[API] saveUserPlaylist called - user: ${userEmail}, playlist: ${playlistId}`);
    return fetchFromAPI('/api/v1/user/playlist', {
      method: 'POST',
      body: JSON.stringify({
        user_email: userEmail,
        playlist_id: playlistId,
        playlist_url: playlistUrl,
        playlist_title: playlistTitle,
        total_videos: totalVideos,
      }),
    });
  },

  saveVideoProgress: (userEmail: string, playlistId: string, videoId: string, watchedSeconds: number, duration: number, completed: boolean) => {
    console.log(`[API] saveVideoProgress - user: ${userEmail}, video: ${videoId}, progress: ${watchedSeconds}/${duration}s, completed: ${completed}`);
    return fetchFromAPI('/api/v1/user/progress', {
      method: 'POST',
      body: JSON.stringify({
        user_email: userEmail,
        playlist_id: playlistId,
        video_id: videoId,
        watched_seconds: watchedSeconds,
        duration: duration,
        completed: completed,
      }),
    });
  },

  getPlaylistProgress: (email: string, playlistId: string) => {
    console.log(`[API] getPlaylistProgress - user: ${email}, playlist: ${playlistId}`);
    return fetchFromAPI(`/api/v1/user/${encodeURIComponent(email)}/playlist/${playlistId}/progress`);
  },

  deleteUserPlaylist: (email: string, playlistId: string) => {
    console.log(`[API] deleteUserPlaylist - user: ${email}, playlist: ${playlistId}`);
    return fetchFromAPI(`/api/v1/user/${encodeURIComponent(email)}/playlist/${playlistId}`, {
      method: 'DELETE',
    });
  },
};
