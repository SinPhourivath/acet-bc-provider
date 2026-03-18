package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

import com.nbc.acet.api.ParameterSet;
import com.nbc.acet.provider.bc.base.BcKemProviderBase;

public class BcMlKem768Provider extends BcKemProviderBase {

    @Override
    public String algorithm() {
        return "ML-KEM";
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
