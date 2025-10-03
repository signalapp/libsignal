package transport

type PreKeyEnvelope struct {
    ID     uint32 `json:"id"`
    Public []byte `json:"public"`
}

type SignedPreKeyEnvelope struct {
    ID        uint32 `json:"id"`
    Public    []byte `json:"public"`
    Signature []byte `json:"signature"`
}

type KyberPreKeyEnvelope struct {
    ID        uint32 `json:"id"`
    Public    []byte `json:"public"`
    Signature []byte `json:"signature"`
}

type BundlePayload struct {
    RegistrationID uint32               `json:"registration_id"`
    DeviceID       uint32               `json:"device_id"`
    PreKey         *PreKeyEnvelope      `json:"pre_key,omitempty"`
    SignedPreKey   SignedPreKeyEnvelope `json:"signed_pre_key"`
    IdentityKey    []byte               `json:"identity_key"`
    KyberPreKey    KyberPreKeyEnvelope  `json:"kyber_pre_key"`
}

