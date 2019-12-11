from __future__ import absolute_import

from twisted.web import http

from .base_endpoint import BaseEndpoint
from ..attestation.noodle.community import NoodleCommunity


class NoodleEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handing all requests regarding the status of the Noodle community.
    """

    def __init__(self, session):
        super(NoodleEndpoint, self).__init__()
        self.session = session

        noodle_overlays = [overlay for overlay in session.overlays if isinstance(overlay, NoodleCommunity)]
        if noodle_overlays:
            self.putChild(b"randomtransfer", NoodleRandomTransferEndpoint(noodle_overlays[0]))


class NoodleRandomTransferEndpoint(BaseEndpoint):

    def __init__(self, noodle_overlay):
        super(NoodleRandomTransferEndpoint, self).__init__()
        self.noodle_overlay = noodle_overlay

    def render_POST(self, request):
        self.noodle_overlay.make_random_transfer()
        return self.twisted_dumps({"success": True})
