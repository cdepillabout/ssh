module SSH.Numbers where

-- | Numbers used in the SSH protocol as defined in
-- <http://tools.ietf.org/html/rfc4250 rfc4250>.

-- | Message IDs for ssh.

-- | Message IDs for the SSH transport protocol.

sshMsgDisconnect :: Word8
sshMsgDisconnect = 1

sshMsgIgnore :: Word8
sshMsgIgnore = 2

sshMsgUnimplemented :: Word8
sshMsgUnimplemented = 3

sshMsgDebug :: Word8
sshMsgDebug = 4

sshMsgServiceRequest :: Word8
sshMsgServiceRequest = 5

sshMsgServiceAccept :: Word8
sshMsgServiceAccept = 6

sshMsgKexinit :: Word8
sshMsgKexinit = 20

sshMsgNewkeys :: Word8
sshMsgNewkeys = 21

-- | Message IDs for the SSH authentication protocol.

sshMsgUserauthRequest :: Word8
sshMsgUserauthRequest = 50

sshMsgUserauthFailure :: Word8
sshMsgUserauthFailure = 51

sshMsgUserauthSuccess :: Word8
sshMsgUserauthSuccess = 52

sshMsgUserauthBanner :: Word8
sshMsgUserauthBanner = 53

-- | Message IDs for the SSH connection protocol.

sshMsgGlobalRequest :: Word8
sshMsgGlobalRequest = 80

sshMsgRequestSuccess :: Word8
sshMsgRequestSuccess = 81

sshMsgRequestFailure :: Word8
sshMsgRequestFailure = 82

sshMsgChannelOpen :: Word8
sshMsgChannelOpen = 90

sshMsgChannelOpenConfirmation :: Word8
sshMsgChannelOpenConfirmation = 91

sshMsgChannelOpenFailure :: Word8
sshMsgChannelOpenFailure = 92

sshMsgChannelWindowAdjust :: Word8
sshMsgChannelWindowAdjust = 93

sshMsgChannelData :: Word8
sshMsgChannelData = 94

sshMsgChannelExtendedData :: Word8
sshMsgChannelExtendedData = 95

sshMsgChannelEof :: Word8
sshMsgChannelEof = 96

sshMsgChannelClose :: Word8
sshMsgChannelClose = 97

sshMsgChannelRequest :: Word8
sshMsgChannelRequest = 98

sshMsgChannelSuccess :: Word8
sshMsgChannelSuccess = 99

sshMsgChannelFailure :: Word8
sshMsgChannelFailure = 100
