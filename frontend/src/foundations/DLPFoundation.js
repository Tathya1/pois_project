import { FoundationInterface } from "./FoundationInterface";

export class DLPFoundation extends FoundationInterface {
  asOWF(input) {
    return "g^" + input + " mod p";
  }

  asOWP(input) {
    return "DLP_OWP(" + input + ")";
  }
}