// Andis-MacBook-Pro.local.:60766
//FA_3C_ED_5A_1A_1A.local.:51826
import uuid from 'uuid/v4'; // Version 4, random uuid

import {HAPClient} from "./HAPClient";

HAPClient.loadClient("B35C857C-5EA4-477D-8C0D-80D29433548E", "FA_3C_ED_5A_1A_1A.local", 51826, callback => {
    callback("031-45-154");
}).then(client => {
    client.establishConnection();
});
