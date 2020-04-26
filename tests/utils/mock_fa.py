from fa import fainterp


class MockFaInterp(fainterp.FaInterp):
    def reload_segments(self):
        pass

    def set_input(self, input_):
        pass

    @property
    def segments(self):
        return self._segments

    @segments.setter
    def segments(self, value):
        """
        Set the current segments
        :param value: Ordered mapping between start addresses and their data
        """
        self._segments = value
