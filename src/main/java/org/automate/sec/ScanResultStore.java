package org.automate.sec;

import org.springframework.stereotype.Component;

@Component
public class ScanResultStore {

    private volatile String latestResult;

    public String getLatestResult() {
        return latestResult;
    }

    public void setLatestResult(String result) {
        this.latestResult = result;
    }
}
