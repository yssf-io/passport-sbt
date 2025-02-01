import React from 'react';
import { Linking, Platform } from 'react-native';
import { Text, YStack, Button } from 'tamagui';
import { textBlack, blueColorDark } from '../utils/colors';
import { STORE_URLS } from '../constants/appUpdate';

const UpdateScreen: React.FC = () => {

  const handleUpdate = () => {
    if (Platform.OS === 'ios') {
      Linking.openURL(STORE_URLS.ios);
    } else {
      Linking.openURL(STORE_URLS.android);
    }
  };

  return (
    <YStack f={1} ai="center" jc="center" p="$4" bg="white">
      <Text fontSize="$8" fontWeight="bold" mb="$4" color={textBlack}>
        Update Required
      </Text>

      <Text fontSize="$6" mb="$6" textAlign="center" color={textBlack}>
        An update is required to continue using the app.
      </Text>

      <Button
        bg={blueColorDark}
        scale={1.1}
        onPress={handleUpdate}
        pressStyle={{ scale: 0.97 }}
      >
        <Text color="white" fontSize="$5" fontWeight="bold">
          Update Now
        </Text>
      </Button>
    </YStack>
  );
};

export default UpdateScreen;
