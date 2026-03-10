package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import com.nbc.acet.api.ParameterSet;
import com.nbc.acet.provider.bc.base.BcSignatureProviderBase;

public class BcRsa2048Provider extends BcSignatureProviderBase {

    @Override
    public String algorithm() {
        return "RSA";
    }

    @Override
    public ParameterSet parameterSet() {
        return ParameterSet.RSA_2048;
    }

    @Override
    protected String keyAlgorithm() {
        return "RSA";
    }

    @Override
    protected String signatureAlgorithm() {
        return "SHA256withRSA";
    }

    @Override
    protected AlgorithmParameterSpec keySpec() {
        return new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
    }
}
