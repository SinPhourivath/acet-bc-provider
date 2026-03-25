package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import com.nbc.acet.api.Algorithm;
import com.nbc.acet.api.ParameterSet;
import com.nbc.acet.provider.bc.base.BcKemProviderBase;

public class BcX25519MLKEM768Provider extends BcKemProviderBase {

    @Override
    public Algorithm algorithm() {
        return Algorithm.X25519_ML_KEM;
    }

    @Override
    public ParameterSet parameterSet() {
        return ParameterSet.X25519MLKEM768;
    }

    @Override
    protected String kemAlgorithm() {
        return "X25519-MLKEM768"; 
    }

    @Override
    protected AlgorithmParameterSpec kemSpec() {
        return null;
    }
}
