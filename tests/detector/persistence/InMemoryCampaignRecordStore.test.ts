import { describeCampaignRecordStoreContract } from "../../../src/test-support/campaignRecordStoreContract.js";
import { InMemoryCampaignRecordStore } from "../../../src/detector/persistence/InMemoryCampaignRecordStore.js";

describeCampaignRecordStoreContract(
  "InMemoryCampaignRecordStore",
  async () => new InMemoryCampaignRecordStore(),
);
