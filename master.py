"""
Yara Automatic Learner v1.0
bunseokbot@UpRoot
"""

import argparse
import os
import time

from libs.yara_learner import YaraLearner


def main(args):
    folder = args.target_folder
    if not os.path.isdir(folder):
        raise Exception("Target File is not a folder type")

    updatetime = args.update_time
    yarafile = args.yara_file
    patternname = args.pattern_name
    count = args.repeat_count
    condition = args.condition_count
    yaraflag = False  # directory : True, file : False

    if not os.path.exists(yarafile):
        raise Exception("Yara File is not exist")

    if os.path.isdir(yarafile):
        yaraflag = True

    while True:
        try:
            yl = YaraLearner(folder, yarafile, yaraflag, patternname, condition, count)
            yl.action()
            del yl
        except:
            import traceback
            print(traceback.format_exc())
        finally:
            time.sleep(updatetime * 60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--target-folder', default='target',
                        type=str, help="folder of de-learning file")
    parser.add_argument('-y', '--yara-file', default='learn.yar',
                        type=str, help="yara file or directory to apply")
    parser.add_argument('-u', '--update-time', default=10,
                        type=int, help="Yara pattern update time (minute)")
    parser.add_argument('-n', '--pattern-name',
                        type=str, help="Learning rule pattern name")
    parser.add_argument('-t', '--pattern-tag',
                        type=list, help="Pattern tag list (Optional)")
    parser.add_argument('-c', '--repeat-count',
                        type=int, help="Pattern insert repeat count", default=3)
    parser.add_argument('-i', '--condition-count',
                        type=str, help="Pattern condition count", default="5")

    args = parser.parse_args()

    if args.pattern_name is not None:
        main(args)
    else:
        print("[ABORTED] Pattern name not found\n"
              "You must have set default pattern name!")
