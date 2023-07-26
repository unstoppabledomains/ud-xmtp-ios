//
//  SigningKey.swift
//
//
//  Created by Pat Nakajima on 11/17/22.
//

import Foundation
import web3
import XMTPRust

/// Defines a type that is used by a ``Client`` to sign keys and messages.
///
/// You can use ``Account`` for an easier WalletConnect flow, or ``PrivateKey``
/// for quick key generation.
///
/// > Tip: You can make your own object that conforms to ``SigningKey`` if you want to
/// handle key management yourself.
public protocol SigningKey {
	/// A wallet address for this key
	var address: String { get }

	/// Sign the data and return a secp256k1 compact recoverable signature.
	func sign(_ data: Data) async throws -> Signature

	/// Pass a personal Ethereum signed message string text to be signed, returning
	/// a secp256k1 compact recoverable signature. You can use ``Signature.ethPersonalMessage`` to generate this text.
	func sign(message: String) async throws -> Signature
}

extension SigningKey {
	func createIdentity(_ identity: PrivateKey) async throws -> AuthorizedIdentity {
		var slimKey = PublicKey()
		slimKey.timestamp = UInt64(Date().millisecondsSinceEpoch)
		slimKey.secp256K1Uncompressed = identity.publicKey.secp256K1Uncompressed

		let signatureText = Signature.createIdentityText(key: try slimKey.serializedData())
		let signature = try await sign(message: signatureText)

		let messageHash = try Signature.ethHash(signatureText)
//		let recoveredKey = try KeyUtilx.recoverPublicKeyKeccak256(from: signature.rawData, message: messageHash)
        let recoveredPublicKey = SECP256K1.recoverPublicKey(hash: messageHash, signature: signature.rawData)
		let address = KeyUtilx.generateAddress(from: recoveredPublicKey!).toChecksumAddress()

		var authorized = PublicKey()
		authorized.secp256K1Uncompressed = slimKey.secp256K1Uncompressed
		authorized.timestamp = slimKey.timestamp
		authorized.signature = signature

		return AuthorizedIdentity(address: address, authorized: authorized, identity: identity)
	}
}

import secp256k1

public struct SECP256K1 {
    
    static let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY))
    
    public struct UnmarshaledSignature{
        public var v: UInt8 = 0
        public var r = Data(repeating: 0, count: 32)
        public var s = Data(repeating: 0, count: 32)
        
        public init(v: UInt8, r: Data, s: Data) {
            self.v = v
            self.r = r
            self.s = s
        }
    }
}

extension SECP256K1 {
    public static func recoverPublicKey(hash: Data, signature: Data, compressed: Bool = false) -> Data? {
        guard hash.count == 32, signature.count == 65 else {return nil}
        guard var recoverableSignature = parseSignature(signature: signature) else {return nil}
        guard var publicKey = SECP256K1.recoverPublicKey(hash: hash, recoverableSignature: &recoverableSignature) else {return nil}
        guard let serializedKey = SECP256K1.serializePublicKey(publicKey: &publicKey, compressed: compressed) else {return nil}
        return serializedKey
    }
    
    public static func serializePublicKey(publicKey: inout secp256k1_pubkey, compressed: Bool = false) -> Data? {
        var keyLength = compressed ? 33 : 65
        var serializedPubkey = Data(repeating: 0x00, count: keyLength)
        let result = serializedPubkey.withUnsafeMutableBytes { (serializedPubkeyRawBuffPointer) -> Int32? in
            if let serializedPkRawPointer = serializedPubkeyRawBuffPointer.baseAddress, serializedPubkeyRawBuffPointer.count > 0 {
                let serializedPubkeyPointer = serializedPkRawPointer.assumingMemoryBound(to: UInt8.self)
                return withUnsafeMutablePointer(to: &keyLength, { (keyPtr:UnsafeMutablePointer<Int>) -> Int32 in
                    withUnsafeMutablePointer(to: &publicKey, { (pubKeyPtr:UnsafeMutablePointer<secp256k1_pubkey>) -> Int32 in
                        let res = secp256k1_ec_pubkey_serialize(context!,
                                                                serializedPubkeyPointer,
                                                                keyPtr,
                                                                pubKeyPtr,
                                                                UInt32(compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))
                        return res
                    })
                })
            } else {
                return nil
            }
        }
        guard let res = result, res != 0 else {
            return nil
        }
        return Data(serializedPubkey)
    }
    
    public static func parseSignature(signature: Data) -> secp256k1_ecdsa_recoverable_signature? {
        guard signature.count == 65 else {return nil}
        var recoverableSignature: secp256k1_ecdsa_recoverable_signature = secp256k1_ecdsa_recoverable_signature()
        let serializedSignature = Data(signature[0..<64])
        var v = Int32(signature[64])
        if v >= 27 && v <= 30 {
            v -= 27
        } else if v >= 31 && v <= 34 {
            v -= 31
        } else if v >= 35 && v <= 38 {
            v -= 35
        }
        let result = serializedSignature.withUnsafeBytes { (serRawBufferPtr: UnsafeRawBufferPointer) -> Int32? in
            if let serRawPtr = serRawBufferPtr.baseAddress, serRawBufferPtr.count > 0 {
                let serPtr = serRawPtr.assumingMemoryBound(to: UInt8.self)
                return withUnsafeMutablePointer(to: &recoverableSignature, { (signaturePointer:UnsafeMutablePointer<secp256k1_ecdsa_recoverable_signature>) -> Int32 in
                    let res = secp256k1_ecdsa_recoverable_signature_parse_compact(context!, signaturePointer, serPtr, v)
                    return res
                })
            } else {
                return nil
            }
        }
        guard let res = result, res != 0 else {
            return nil
        }
        return recoverableSignature
    }
    
    internal static func recoverPublicKey(hash: Data, recoverableSignature: inout secp256k1_ecdsa_recoverable_signature) -> secp256k1_pubkey? {
        guard hash.count == 32 else {return nil}
        var publicKey: secp256k1_pubkey = secp256k1_pubkey()
        let result = hash.withUnsafeBytes({ (hashRawBufferPointer: UnsafeRawBufferPointer) -> Int32? in
            if let hashRawPointer = hashRawBufferPointer.baseAddress, hashRawBufferPointer.count > 0 {
                let hashPointer = hashRawPointer.assumingMemoryBound(to: UInt8.self)
                return withUnsafePointer(to: &recoverableSignature, { (signaturePointer:UnsafePointer<secp256k1_ecdsa_recoverable_signature>) -> Int32 in
                    withUnsafeMutablePointer(to: &publicKey, { (pubKeyPtr: UnsafeMutablePointer<secp256k1_pubkey>) -> Int32 in
                        let res = secp256k1_ecdsa_recover(context!, pubKeyPtr,
                                                          signaturePointer, hashPointer)
                        return res
                    })
                })
            } else {
                return nil
            }
        })
        guard let res = result, res != 0 else {
            return nil
        }
        return publicKey
    }
}
