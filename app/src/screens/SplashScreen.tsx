import React, { useEffect, useState } from 'react';

import { Spinner, Text, XStack, YStack } from 'tamagui';

import useNavigationStore from '../stores/navigationStore';
import useUserStore from '../stores/userStore';
import { textBlack } from '../utils/colors';
import { checkForUpdate, UpdateCheckState } from '../utils/updateChecker';

const SplashScreen = () => {
  const { userLoaded, passportData, passportMetadata } = useUserStore();
  const [updateState, setUpdateState] = useState<UpdateCheckState>({
    updateChecked: false,
    error: null,
  });
  const { setSelectedTab } = useNavigationStore();

  useEffect(() => {
    const checkAppUpdate = async () => {
      try {
        if (!updateState.updateChecked) {
          const { isUpdateNeeded } = await checkForUpdate();
          setUpdateState({ updateChecked: true, error: null });

          if (isUpdateNeeded) {
            setSelectedTab('update');
            return true;
          }
        }
        return false;
      } catch (error: any) {
        const errorMessage = error?.message ?? 'Unknown error';
        console.error(`Error checking for update: ${errorMessage}`);
        setUpdateState({ updateChecked: true, error: errorMessage });
        return false;
      }
    };

    const setInitialTab = () => {
      if (!userLoaded) {return;}

      if (passportData &&
          passportMetadata &&
          passportData.dg2Hash &&
          !passportData.mockUser
      ) {
        setSelectedTab('app');
      } else {
        setSelectedTab('start');
      }
    };

    const initialize = async () => {
      const updateNeeded = await checkAppUpdate();
      if (!updateNeeded) {
        setInitialTab();
      }
    };

    initialize();
  }, [userLoaded]);

  return (
    <YStack ai="center" f={1} gap="$8" mt="$18" mb="$8">
      <Text fontSize="$9">OpenPassport</Text>
      <XStack f={1} />
      <Spinner color={textBlack} />
    </YStack>
  );
};

export default SplashScreen;
