package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

import com.nbc.acet.api.ParameterSet;
import com.nbc.acet.provider.bc.base.BcSignatureProviderBase;

public class BcMlDsa65Provider extends BcSignatureProviderBase {

    @Override
    public String algorithm() {
        return "ML-DSA";
    }

    @Override
    public ParameterSet parameterSet() {
        return ParameterSet.ML_DSA_65;
    }

    @Override
    protected String keyAlgorithm() {
        return "ML-DSA";
    }

    @Override
    protected String signatureAlgorithm() {
        return "ML-DSA-65";
    }

    @Override
    protected AlgorithmParameterSpec keySpec() {
        return MLDSAParameterSpec.ml_dsa_65;
    }
}
