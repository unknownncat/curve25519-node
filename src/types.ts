declare const bytes32Brand: unique symbol;
declare const bytes64Brand: unique symbol;

export type Bytes32 = Uint8Array & { readonly __brand: typeof bytes32Brand };
export type Bytes64 = Uint8Array & { readonly __brand: typeof bytes64Brand };

export interface KeyPair32 {
  public: Bytes32;
  private: Bytes32;
}
