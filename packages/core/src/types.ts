export type Bytes32 = Uint8Array & { readonly __brand: "Bytes32" };
export type Bytes64 = Uint8Array & { readonly __brand: "Bytes64" };

export interface KeyPair32 {
  public: Bytes32;
  private: Bytes32;
}
