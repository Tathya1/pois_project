import { FoundationInterface } from "./FoundationInterface";

export class AESFoundation extends FoundationInterface {
  asPRF(input) {
    return "AES_PRF(" + input + ")";
  }

  asPRP(input) {
    return "AES_PRP(" + input + ")";
  }

  asOWF(input) {
    return "AES_OWF(" + input + ")";
  }
}