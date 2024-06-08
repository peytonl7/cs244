# CS 244: Final Project (Stanford)

Stanford's network performs much stricter TCP window checking than the authors
anticipate. In order to not get dropped, we find that a TCP segment must have:
 * its sequence number within 2Gi before the largest right window edge observed,
   and
 * its acknowlegment number within 128Ki before the largest sequence number
   observed.

This branch modifies the `hijack-stream` program in light of these constraints.
This means the attack takes much longer, since a total of 64Ki packets have to
be sent. We recommend reducing the inter-packet delay as much as possible to
compensate.

## TODO
* [ ] Apply the same change to `close-stream`
