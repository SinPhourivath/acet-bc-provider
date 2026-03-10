package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.ECNamedCurveTable;

import com.nbc.acet.api.ParameterSet;
import com.nbc.acet.provider.bc.base.BcSignatureProviderBase;

public class BcEcdsaP256Provider extends BcSignatureProviderBase {

    @Override
    public String algorithm() {
        return "ECDSA";
    }

    @Override
    public ParameterSet parameterSet() {
        return ParameterSet.ECDSA_P256;
    }

    @Override
    protected String keyAlgorithm() {
        return "EC";
    }

    @Override
    protected String signatureAlgorithm() {
        return "SHA256withECDSA";
    }

    @Override
    protected AlgorithmParameterSpec keySpec() {
        return ECNamedCurveTable.getParameterSpec("P-256");
    }
}
