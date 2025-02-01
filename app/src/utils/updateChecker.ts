import axios, { AxiosError } from 'axios';
import { Platform } from 'react-native';
import { APP_UPDATE_API_URL, APP_VERSION, STORE_URLS } from '../constants/appUpdate';

type UpdateCheckerResponse = {
    isUpdateNeeded: boolean;
    updateUrl: string;
}

export type UpdateCheckState = {
    updateChecked: boolean;
    error: string | null;
}

const UPDATE_CHECK_TIMEOUT = 5000; // 5 seconds
const MAX_RETRIES = 3;

export async function checkForUpdate(): Promise<UpdateCheckerResponse> {
  let retries = 0;

  while (retries < MAX_RETRIES) {
    try {

      console.log('Checking for updates...', { currentVersion: APP_VERSION });
      const updateCheckUrl = `${APP_UPDATE_API_URL}?platform=${Platform.OS}&version=${APP_VERSION}`;
      const response = await axios.get<UpdateCheckerResponse>(updateCheckUrl, {
        timeout: UPDATE_CHECK_TIMEOUT,
      });

      // Add default store URL
      const updateUrl = response.data.updateUrl ||
        (Platform.OS === 'ios' ? STORE_URLS.ios : STORE_URLS.android);

      return {
        ...response.data,
        updateUrl,
      };

    } catch (error) {
      retries++;
      const isLastRetry = retries === MAX_RETRIES;

      if (error instanceof AxiosError) {
        console.error('Update check failed:', {
          attempt: retries,
          error: error.message,
        });
      }

      if (isLastRetry) {
        throw new Error('Failed to check for updates after multiple attempts');
      }

      // Wait before retry (exponential backoff)
      await new Promise(resolve => setTimeout(resolve, 1000 * retries));
    }
  }

  // Fallback response if all retries fail
  return {
    isUpdateNeeded: false,
    updateUrl: '',
  };
}
