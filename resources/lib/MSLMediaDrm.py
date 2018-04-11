from ctypes import *
from os import urandom
import json
import base64

class AMediaDrmByteArray(Structure):
  _fields_ = [("ptr", c_char_p), ("length", c_ulong)]

class MSLMediaDrmCrypto:

  KEY_TYPE_STREAMING = c_int(1)
  KEY_TYPE_OFFLINE = c_int(2)
  KEY_TYPE_RELEASE = c_int(3)


  AMEDIA_OK = 0
  AMEDIA_ERROR_BASE = -10000
  AMEDIA_ERROR_UNKNOWN = AMEDIA_ERROR_BASE
  AMEDIA_ERROR_MALFORMED = AMEDIA_ERROR_BASE - 1
  AMEDIA_ERROR_UNSUPPORTED = AMEDIA_ERROR_BASE - 2
  AMEDIA_ERROR_INVALID_OBJECT = AMEDIA_ERROR_BASE - 3
  AMEDIA_ERROR_INVALID_PARAMETER = AMEDIA_ERROR_BASE - 4
  AMEDIA_ERROR_INVALID_OPERATION = AMEDIA_ERROR_BASE - 5
  AMEDIA_DRM_ERROR_BASE = -20000
  AMEDIA_DRM_NOT_PROVISIONED = AMEDIA_DRM_ERROR_BASE - 1
  AMEDIA_DRM_RESOURCE_BUSY = AMEDIA_DRM_ERROR_BASE - 2
  AMEDIA_DRM_DEVICE_REVOKED = AMEDIA_DRM_ERROR_BASE - 3
  AMEDIA_DRM_SHORT_BUFFER = AMEDIA_DRM_ERROR_BASE - 4
  AMEDIA_DRM_SESSION_NOT_OPENED = AMEDIA_DRM_ERROR_BASE - 5
  AMEDIA_DRM_TAMPER_DETECTED = AMEDIA_DRM_ERROR_BASE - 6
  AMEDIA_DRM_VERIFY_FAILED = AMEDIA_DRM_ERROR_BASE - 7
  AMEDIA_DRM_NEED_KEY = AMEDIA_DRM_ERROR_BASE - 8
  AMEDIA_DRM_LICENSE_EXPIRED = AMEDIA_DRM_ERROR_BASE - 9

  def __init__(self, kodi_helper):
    self.libMediaDrm = cdll.LoadLibrary('/system/lib/libmediandk.so')
    self.kodi_helper = kodi_helper
    self.sessionStatus = self.AMEDIA_DRM_SESSION_NOT_OPENED

    self.key_set_id = None
    self.key_id = None

    # Create MediaDrm with widevine UUID
    AMediaDrm_createByUUID = self.libMediaDrm.AMediaDrm_createByUUID
    self.mediaDrm = AMediaDrm_createByUUID('\xed\xef\x8b\xa9\x79\xd6\x4a\xce\xa3\xc8\x27\xdc\xd5\x1d\x21\xed')
    self.kodi_helper.log(msg='MediaDrm Instance:' + hex(self.mediaDrm))

    # get the systemId property
    AMediaDrm_getPropertyString = self.libMediaDrm.AMediaDrm_getPropertyString
    self.systemId = c_char_p()
    status = AMediaDrm_getPropertyString(self.mediaDrm, 'systemId', byref(self.systemId))
    self.kodi_helper.log(msg='MediaDrm: status:' + str(status) + " systemId:" + self.systemId.value)

    if status == self.AMEDIA_OK:
      self.__openSession()

  def __del__(self):
    if self.sessionStatus ==  self.AMEDIA_OK:
      self.kodi_helper.log(msg='MediaDrm removing keys...')
      key_set_id = AMediaDrmByteArray(cast(self.keySetId, c_char_p), len(self.keySetId))
      AMediaDrm_removeKeys = self.libMediaDrm.AMediaDrm_removeKeys
      AMediaDrm_removeKeys(self.mediaDrm, byref(key_set_id))
      self.kodi_helper.log(msg='closing session...')
      self.__closeSession()

    if self.mediaDrm:
      self.kodi_helper.log(msg='releasing DRM...')
      AMediaDrm_release =  self.libMediaDrm.AMediaDrm_release
      AMediaDrm_release(self.mediaDrm)

  def getSystemId(self):
    return self.systemId.value

  def __openSession(self):
    AMediaDrm_openSession = self.libMediaDrm.AMediaDrm_openSession
    self.sessionId = AMediaDrmByteArray()
    self.sessionStatus = AMediaDrm_openSession(self.mediaDrm, byref(self.sessionId))
    self.kodi_helper.log(msg='MediaDrm sessionId open: status:' + str(self.sessionStatus) + ', size:' + str(self.sessionId.length))
    return self.sessionStatus == self.AMEDIA_OK

  def __closeSession(self):
    AMediaDrm_closeSession = self.libMediaDrm.AMediaDrm_closeSession
    status = AMediaDrm_closeSession(self.mediaDrm, byref(self.sessionId))
    self.kodi_helper.log(msg='MediaDrm session closed: status:' + str(status))
    self.sessionStatus = self.AMEDIA_DRM_SESSION_NOT_OPENED

  def __getKeyRequest(self, data):
    AMediaDrm_getKeyRequest = self.libMediaDrm.AMediaDrm_getKeyRequest
    keyRequestPtr = c_char_p()
    keyRequestLength = c_ulong()
    status = AMediaDrm_getKeyRequest(
      self.mediaDrm,
      byref(self.sessionId),
      cast(data, c_char_p),
      c_ulong(len(data)),
      '',
      self.KEY_TYPE_OFFLINE,
      None,
      0,
      byref(keyRequestPtr),
      byref(keyRequestLength))

    self.kodi_helper.log(msg='MediaDrm getKeyRequest status:' + str(status) + ', size:' + str(keyRequestLength))

    if status == self.AMEDIA_DRM_NOT_PROVISIONED:
      #TODO: Make provisioning request
      pass

    return string_at(keyRequestPtr, keyRequestLength.value)

  def __provideKeyResponse(self, data):
    if len(data) == 0:
      return false
    AMediaDrm_provideKeyResponse = self.libMediaDrm.AMediaDrm_provideKeyResponse
    keySetId = AMediaDrmByteArray()

    status = AMediaDrm_provideKeyResponse(self.mediaDrm, byref(self.sessionId), cast(data, c_char_p), c_ulong(len(data)), byref(keySetId))

    self.keySetId = string_at(keySetId.ptr, keySetId.length)

    return status == self.AMEDIA_OK

  def toDict(self):
    self.kodi_helper.log(msg='Provide Widevine keys to dict')
    data = {
      "key_set_id": base64.standard_b64encode(self.keySetId),
      'key_id': base64.standard_b64encode(self.keyId),
      'hmac_key_id': base64.standard_b64encode(self.hmacKeyId)
    }
    return data

  def fromDict(self, msl_data):
    need_handshake = False

    if self.sessionStatus != self.AMEDIA_OK:
       return False

    try:
      self.kodi_helper.log(msg='Parsing Widevine keys from Dict')
      self.keySetId = base64.standard_b64decode(msl_data['key_set_id'])
      self.keyId = base64.standard_b64decode(msl_data['key_id'])
      self.hmacKeyId = base64.standard_b64decode(msl_data['hmac_key_id'])

      AMediaDrm_restoreKeys = self.libMediaDrm.AMediaDrm_restoreKeys

      key_set_id = AMediaDrmByteArray(cast(self.keySetId, c_char_p), len(self.keySetId))
      status = AMediaDrm_restoreKeys(self.mediaDrm, byref(self.sessionId), byref(key_set_id))

      if status != self.AMEDIA_OK:
        need_handshake = True

    except:
      need_handshake = True

    return need_handshake

  def get_key_request(self):
    if self.sessionStatus != self.AMEDIA_OK:
       return

    drmKeyRequest = self.__getKeyRequest(bytes([10, 122, 0, 108, 56, 43]))

    key_request = [{
    'scheme': 'WIDEVINE',
    'keydata': {
      'keyrequest': base64.standard_b64encode(drmKeyRequest)
    }
    }]

    return key_request

  def parse_key_response(self, headerdata):
    # Init Decryption
    key_resonse = base64.standard_b64decode(headerdata['keyresponsedata']['keydata']['cdmkeyresponse'])

    if not self.__provideKeyResponse(key_resonse):
      return

    self.keyId = base64.standard_b64decode(headerdata['keyresponsedata']['keydata']['encryptionkeyid'])
    self.hmacKeyId = base64.standard_b64decode(headerdata['keyresponsedata']['keydata']['hmackeyid'])

  def decrypt(self, iv, data):
    AMediaDrm_decrypt = self.libMediaDrm.AMediaDrm_decrypt
    resultBuffer = bytes(len(data))
    status = AMediaDrm_decrypt(self.mediaDrm,
      byref(self.sessionId),
      'AES/CBC/NoPadding',
      cast(self.keyId, c_char_p),
      cast(iv, c_char_p),
      cast(data, c_char_p),
      cast(resultBuffer, c_char_p),
      cast(len(data), c_ulong))
    self.kodi_helper.log(msg='MediaDrm decrypt status:' + str(status))

    return resultBuffer

  def encrypt(self, data):
    AMediaDrm_encrypt = self.libMediaDrm.AMediaDrm_encrypt
    resultBuffer = bytes(len(data))
    iv = os.urandom(16)

    status = AMediaDrm_encrypt(self.mediaDrm,
      byref(self.sessionId),
      'AES/CBC/NoPadding',
      cast(self.keyId, c_char_p),
      cast(iv, c_char_p),
      cast(data, c_char_p),
      cast(resultBuffer, c_char_p),
      cast(len(data), c_ulong))
    self.kodi_helper.log(msg='MediaDrm encrypt status:' + str(status))

    return resultBuffer

  def sign(self, message):
    AMediaDrm_sign = self.libMediaDrm.AMediaDrm_sign

    signaturePtr = c_char_p()
    signatureLength = c_ulong()
    status = AMediaDrm_sign(self.mediaDrm,
      byref(self.sessionId),
      'JcaAlgorithm.HMAC_SHA256',
      cast(self.hmacKeyId, c_char_p),
      cast(message, c_char_p),
      cast(len(message), c_ulong),
      signaturePtr,
      signatureLength)
    self.kodi_helper.log(msg='MediaDrm sign status:' + str(status) + ', signature length:' + str(signatureLength))

    return AMediaDrmByteArray(signaturePtr, signatureLength)

  def verify(self, message, signature):
    AMediaDrm_verify = self.libMediaDrm.AMediaDrm_verify
    status = AMediaDrm_verify(self.mediaDrm,
      byref(self.sessionId),
      'JcaAlgorithm.HMAC_SHA256',
      cast(self.hmacKeyId, c_char_p),
      cast(message, c_char_p),
      cast(len(message), c_ulong),
      cast(signature, c_char_p),
      cast(len(signature), c_ulong))
    print 'MediaDrm verify status:' + str(status)

    return status == self.AMEDIA_OK
