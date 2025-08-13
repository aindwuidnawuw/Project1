pragma circom 2.2.2;

template Exp5Box() {
    signal input inVal;
    signal output outVal;

    signal sq;   
    signal quad;
    sq <== inVal * inVal;        
    quad <== sq * sq;             
    outVal <== quad * inVal;      
}

template Poseidon2Step(typeFlag, rIndex, width, nRounds) {
    signal input stateIn[width];
    signal output stateOut[width];

    var MDS[3][3] = [
        [2, 1, 1],
        [1, 2, 1],
        [1, 1, 2]
    ];

    var RC[64][3];
    for (var rr = 0; rr < 64; rr++) {
        for (var cc = 0; cc < 3; cc++) {
            RC[rr][cc] = rr * 3 + cc + 10; 
        }
    }

    signal afterRC[width];
    for (var k = 0; k < width; k++) {
        afterRC[k] <== stateIn[k] + RC[rIndex][k];
    }

    signal afterSB[width];
    component box[width];

    if (typeFlag == 0) {
        for (var k = 0; k < width; k++) {
            box[k] = Exp5Box();
            box[k].inVal <== afterRC[k];
            afterSB[k] <== box[k].outVal;
        }
    } else {
 
        box[0] = Exp5Box();
        box[0].inVal <== afterRC[0];
        afterSB[0] <== box[0].outVal;
        for (var m = 1; m < width; m++) {
            afterSB[m] <== afterRC[m];
        }
    }

    for (var r = 0; r < width; r++) {
        stateOut[r] <== (MDS[r][0] * afterSB[0]) +
                        (MDS[r][1] * afterSB[1]) +
                        (MDS[r][2] * afterSB[2]);
    }
}

template Poseidon2Main() {
    var RF = 8;
    var RP = 56;
    var total = RF + RP;
    var tSize = 3;

    signal input priv[tSize - 1];
    signal input hashOut;

    signal allStates[total + 1][tSize];
    allStates[0][0] <== priv[0];
    allStates[0][1] <== priv[1];
    allStates[0][2] <== 0;

    component step[total];
    for (var r = 0; r < total; r++) {
        var useFull = (r < RF/2) || (r >= total - RF/2) ? 0 : 1;
        step[r] = Poseidon2Step(useFull, r, tSize, total);

        for (var c = 0; c < tSize; c++) {
            step[r].stateIn[c] <== allStates[r][c];
        }
        for (var c = 0; c < tSize; c++) {
            allStates[r+1][c] <== step[r].stateOut[c];
        }
    }

    hashOut === allStates[total][0];
}

component main = Poseidon2Main();
