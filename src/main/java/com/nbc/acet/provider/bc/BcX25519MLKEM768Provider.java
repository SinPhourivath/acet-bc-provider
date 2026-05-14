package com.nbc.acet.provider.bc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMExtractor;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;

import com.nbc.acet.api.X25519MlKemParameterSet;
import com.nbc.acet.api.X25519MlKemProvider;

public class BcX25519MLKEM768Provider implements X25519MlKemProvider {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String provider() {
        return "BouncyCastle-1.84";
    }

    @Override
    public X25519MlKemParameterSet parameterSet() {
        return X25519MlKemParameterSet.X25519MLKEM768;
    }

    @Override
    public KeyPairResult generateKeyPair() {
        XWingKeyPairGenerator generator = new XWingKeyPairGenerator();
        generator.init(new XWingKeyGenerationParameters(RANDOM));
        var keyPair = generator.generateKeyPair();
        var publicKey = (XWingPublicKeyParameters) keyPair.getPublic();
        var privateKey = (XWingPrivateKeyParameters) keyPair.getPrivate();
        return new KeyPairResult(publicKey.getEncoded(), privateKey.getEncoded());
    }

    @Override
    public EncapsulationResult encapsulate(byte[] publicKey) {
        SecretWithEncapsulation encapsulated = new XWingKEMGenerator(RANDOM)
                .generateEncapsulated(new XWingPublicKeyParameters(publicKey));
        return new EncapsulationResult(encapsulated.getSecret(), encapsulated.getEncapsulation());
    }

    @Override
    public byte[] decapsulate(byte[] encapsulation, byte[] privateKey) {
        return new XWingKEMExtractor(new XWingPrivateKeyParameters(privateKey))
                .extractSecret(encapsulation);
    }
}
