package com.nbc.acet.provider.bc;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.ECNamedCurveTable;

import com.nbc.acet.api.Algorithm;
import com.nbc.acet.api.ParameterSet;
import com.nbc.acet.provider.bc.base.BcKeyAgreementProviderBase;

public class BcECDH32Provider extends BcKeyAgreementProviderBase {

    @Override
    public Algorithm algorithm() {
        return Algorithm.ECDH;
    }

    @Override
    public ParameterSet parameterSet() {
        return ParameterSet.ECDH_P256;
    }

    @Override
    protected String keyAlgorithm() {
        return "EC";
    }

    @Override
    protected String agreementAlgorithm() {
        return "ECDH";
    }

    @Override
    protected AlgorithmParameterSpec keySpec() {
        return ECNamedCurveTable.getParameterSpec("P-256");
    }
}
