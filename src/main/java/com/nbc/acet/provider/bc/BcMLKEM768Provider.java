package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

import com.nbc.acet.api.Algorithm;
import com.nbc.acet.api.ParameterSet;
import com.nbc.acet.provider.bc.base.BcKemProviderBase;

public class BcMLKEM768Provider extends BcKemProviderBase {

    @Override
    public Algorithm algorithm() {
        return Algorithm.ML_KEM;
    }

    @Override
    public ParameterSet parameterSet() {
        return ParameterSet.ML_KEM_768;
    }

    @Override
    protected String kemAlgorithm() {
        return "ML-KEM";
    }

    @Override
    protected AlgorithmParameterSpec kemSpec() {
        return MLKEMParameterSpec.ml_kem_768;
    }
}
