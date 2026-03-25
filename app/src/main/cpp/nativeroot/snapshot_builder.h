#ifndef DUCKDETECTOR_NATIVEROOT_SNAPSHOT_BUILDER_H
#define DUCKDETECTOR_NATIVEROOT_SNAPSHOT_BUILDER_H

#include "nativeroot/common/types.h"

namespace duckdetector::nativeroot {

Snapshot collect_snapshot(bool skip_ksu_supercall);

}  // namespace duckdetector::nativeroot

#endif  // DUCKDETECTOR_NATIVEROOT_SNAPSHOT_BUILDER_H
