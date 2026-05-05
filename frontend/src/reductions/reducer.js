import { routingTable } from "./routingTable";

export function reduce(source, target) {
  const key = `${source}->${target}`;

  if (routingTable[key]) {
    return routingTable[key];
  }

  return ["No direct reduction path available"];
}