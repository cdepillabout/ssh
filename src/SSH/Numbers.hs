module SSH.Numbers where

import Data.Word (Word8)

-- | Numbers used in the SSH protocol as defined in
-- <http://tools.ietf.org/html/rfc4250 rfc4250>.

-- | Message IDs for ssh.

data SSHMsgNumber = SSHMsgNumber Word8

-- | Message IDs for the SSH transport protocol.

sshMsgDisconnect :: SSHMsgNumber
sshMsgDisconnect = SSHMsgNumber 1

sshMsgIgnore :: SSHMsgNumber
sshMsgIgnore = SSHMsgNumber 2

sshMsgUnimplemented :: SSHMsgNumber
sshMsgUnimplemented = SSHMsgNumber 3

sshMsgDebug :: SSHMsgNumber
sshMsgDebug = SSHMsgNumber 4

sshMsgServiceRequest :: SSHMsgNumber
sshMsgServiceRequest = SSHMsgNumber 5

sshMsgServiceAccept :: SSHMsgNumber
sshMsgServiceAccept = SSHMsgNumber 6

sshMsgKexinit :: SSHMsgNumber
sshMsgKexinit = SSHMsgNumber 20

sshMsgNewkeys :: SSHMsgNumber
sshMsgNewkeys = SSHMsgNumber 21

-- | Message IDs for the SSH authentication protocol.

sshMsgUserauthRequest :: SSHMsgNumber
sshMsgUserauthRequest = SSHMsgNumber 50

sshMsgUserauthFailure :: SSHMsgNumber
sshMsgUserauthFailure = SSHMsgNumber 51

sshMsgUserauthSuccess :: SSHMsgNumber
sshMsgUserauthSuccess = SSHMsgNumber 52

sshMsgUserauthBanner :: SSHMsgNumber
sshMsgUserauthBanner = SSHMsgNumber 53

-- | Message IDs for the SSH connection protocol.

sshMsgGlobalRequest :: SSHMsgNumber
sshMsgGlobalRequest = SSHMsgNumber 80

sshMsgRequestSuccess :: SSHMsgNumber
sshMsgRequestSuccess = SSHMsgNumber 81

sshMsgRequestFailure :: SSHMsgNumber
sshMsgRequestFailure = SSHMsgNumber 82

sshMsgChannelOpen :: SSHMsgNumber
sshMsgChannelOpen = SSHMsgNumber 90

sshMsgChannelOpenConfirmation :: SSHMsgNumber
sshMsgChannelOpenConfirmation = SSHMsgNumber 91

sshMsgChannelOpenFailure :: SSHMsgNumber
sshMsgChannelOpenFailure = SSHMsgNumber 92

sshMsgChannelWindowAdjust :: SSHMsgNumber
sshMsgChannelWindowAdjust = SSHMsgNumber 93

sshMsgChannelData :: SSHMsgNumber
sshMsgChannelData = SSHMsgNumber 94

sshMsgChannelExtendedData :: SSHMsgNumber
sshMsgChannelExtendedData = SSHMsgNumber 95

sshMsgChannelEof :: SSHMsgNumber
sshMsgChannelEof = SSHMsgNumber 96

sshMsgChannelClose :: SSHMsgNumber
sshMsgChannelClose = SSHMsgNumber 97

sshMsgChannelRequest :: SSHMsgNumber
sshMsgChannelRequest = SSHMsgNumber 98

sshMsgChannelSuccess :: SSHMsgNumber
sshMsgChannelSuccess = SSHMsgNumber 99

sshMsgChannelFailure :: SSHMsgNumber
sshMsgChannelFailure = SSHMsgNumber 100
