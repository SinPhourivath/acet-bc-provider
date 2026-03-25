package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

import com.nbc.acet.api.Algorithm;
import com.nbc.acet.api.ParameterSet;
import com.nbc.acet.provider.bc.base.BcSignatureProviderBase;

public class BcMLDSA65Provider extends BcSignatureProviderBase {

    @Override
    public Algorithm algorithm() {
        return Algorithm.ML_DSA;
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
